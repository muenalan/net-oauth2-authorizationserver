package Net::OAuth2::AuthorizationServer::Callbacks::ExampleDB;

use strict;
use warnings;

use Carp qw(carp cluck);

#use Carp::Always;

use Data::Dump qw(pp);


my $resource_owner_logged_in_sub = sub {

  my $args = {@_};

  my ( $c ) = ( $args->{mojo_controller} );

  if ( ! $c->session( 'logged_in' ) ) {
    # we need to redirect back to the /oauth/authorize route after
    # login (with the original params)
    my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
    $c->flash( 'redirect_after_login' => $uri );
    $c->redirect_to( '/oauth/login' );
    return 0;
  }

  return 1;
};



my $resource_owner_confirm_scopes_sub = sub
{
    my ( %args ) = @_;
 
  my ( $obj,$client_id,$scopes_ref,$redirect_uri,$response_type ) = @args{ qw/ mojo_controller client_id scopes redirect_uri response_type / };
 
    my $error;
    
    my $is_allowed = $obj->flash( "oauth_${client_id}" );
 
  # if user hasn't yet allowed the client access, or if they denied
  # access last time, we check [again] with the user for access
    
    if ( ! $is_allowed )
    {
	    $obj->flash( client_id => $client_id );
	    $obj->flash( scopes    => $scopes_ref );
 
    # we need to redirect back to the /oauth/authorize route after
    # confirm/deny by resource owner (with the original params)
	    my $uri = join( '?',$obj->url_for('current'),$obj->url_with->query );
	    
	    $obj->flash( 'redirect_after_login' => $uri );

	    $obj->app->log->debug( "resource_owner_confirm_scopes_sub: is_allowed not found, will redirect to confirm_scopes" );

#	    cluck "Will try to redirect to confirm scopes..";

	    $obj->redirect_to( '/oauth/confirm_scopes' );

	    return undef;
    }
 
    return ( $is_allowed,$error,$scopes_ref );
};





my $verify_client_sub = sub
{
  my ( %args ) = @_;
 
  my ( $obj,$client_id,$scopes_ref,$client_secret,$redirect_uri,$response_type )  = @args{ qw/ mojo_controller client_id scopes client_secret redirect_uri response_type / };
 
  if (my $client = $obj->db->get_collection( 'clients' )->find_one({ client_id => $client_id }))
  {
      my $client_scopes = [];
 
      # Check scopes
      foreach my $scope ( @{ $scopes_ref // [] } ) 
      {
    if( $ENV{EXAMPLEDB_DEBUG} )
    {
	  $obj->app->log->debug( "verify_client_sub exists scope ? ", $scope );
	  $obj->app->log->debug( "verify_client_sub client has scopes: ".pp( $client->{scopes} ) );
    }

        if ( ! exists( $client->{scopes}->{$scope} ) )
	{
          return ( 0,'invalid_scope' );
        }
	elsif ( $client->{scopes}->{$scope} )
	{
          push @{$client_scopes}, $scope;
        }
      }
 
      # Implicit Grant Checks
      if ( $response_type && $response_type eq 'token' ) {
        # If 'credentials' have been assigned Implicit Grant should be prevented, so check for secret
        return (0, 'unauthorized_grant') if $client->{'secret'};
 
        # Check redirect_uri
        return (0, 'access_denied')   if (
		$client->{'redirect_uri'} &&
	       (!$redirect_uri || $redirect_uri ne $client->{'redirect_uri'}) );
      }
 
      # Credentials Grant Checks
      if ($client_secret && $client_secret ne $client->{'secret'}) {
          return (0, 'access_denied');
      }
 
      return ( 1, undef, $client_scopes );
      
  }


  return ( 0,'unauthorized_client' );
};


my $store_auth_code_sub = sub {

  my $args = {@_};
    
  my ( $c,$auth_code,$client_id,$expires_in,$uri ) = map { $args->{$_} } qw(mojo_controller auth_code client_id expires_in redirect_uri);

    my @scopes = @{ $args->{scopes} };

  my $auth_codes = $c->db->get_collection( 'auth_codes' );

  my $id = $auth_codes->insert_one({
    auth_code    => $auth_code,
    client_id    => $client_id,
    user_id      => $c->session( 'user_id' ),
    expires      => time + $expires_in,
    redirect_uri => $uri,
    scope        => { map { $_ => 1 } @scopes },
  });

  return;
};

my $verify_auth_code_sub = sub {

    my $args = {@_};

  my ( $c,$client_id,$client_secret,$auth_code,$uri ) = map { $args->{$_} } qw(mojo_controller client_id client_secret auth_code redirect_uri);

  my $auth_codes      = $c->db->get_collection( 'auth_codes' );

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
    $c->app->log->debug( "auth_codes collection =", $auth_codes );
    }

  my $ac              = $auth_codes->find_one({
    client_id => $client_id,
    auth_code => $auth_code,
  });

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( "auth_code ac=".pp( $ac ) );
    }

  my $client = $c->db->get_collection( 'clients' )->find_one({ client_id => $client_id });

  $client || return ( 0,'unauthorized_client' );

  if (
    ! $ac
    or $ac->{verified}
    or ( $uri ne $ac->{redirect_uri} )
    or ( $ac->{expires} <= time )
    or ( $client_secret ne $client->{client_secret} )
  ) {
    $c->app->log->debug( "OAuth2::Server: Auth code does not exist" )
      if ! $ac;
    $c->app->log->debug( "OAuth2::Server: Client secret does not match" )
      if ( $uri && $ac->{redirect_uri} ne $uri );
    $c->app->log->debug( "OAuth2::Server: Auth code expired" )
      if ( $ac->{expires} <= time );
    $c->app->log->debug( "OAuth2::Server: Client secret does not match" )
      if ( $client_secret ne $client->{client_secret} );

    if ( $ac->{verified} ) {
      # the auth code has been used before - we must revoke the auth code
      # and access tokens
      $c->app->log->debug(
        "OAuth2::Server: Auth code already used to get access token"
      );

      $auth_codes->delete_one({ auth_code => $auth_code });
      
      $c->db->get_collection( 'access_tokens' )->delete_one({
        access_token => $ac->{access_token}
      });
    }

    return ( 0,'invalid_grant' );
  }

  # scopes are those that were requested in the authorization request, not
  # those stored in the client (i.e. what the auth request restriced scopes
  # to and not everything the client is capable of)
  my $scope = $ac->{scope};

#  $auth_codes->update( $ac,{ verified => 1 } );
#  $auth_codes->replace_one( $ac,{ verified => 1 } );

  $ac->{ verified } = 1;

    $auth_codes->replace_one( { _id => $ac->{_id} }, $ac, { upsert => 1 } );

  return ( $client_id,undef,$scope,$ac->{user_id} );
};


my $store_access_token_sub = sub {
    my ( %args ) = @_;
 
  my (
    $obj,$client,$auth_code,$access_token,$refresh_token,
    $expires_in,$scope,$old_refresh_token
      ) = @args{qw/
    mojo_controller client_id auth_code access_token
    refresh_token expires_in scopes old_refresh_token
    / };

    $obj->app->log->debug( "store_access_token_sub called" );
 
    my $access_tokens  = $obj->db->get_collection( 'access_tokens' );
    my $refresh_tokens = $obj->db->get_collection( 'refresh_tokens' );
 
    my $user_id;
 
    if ( ! defined( $auth_code ) && $old_refresh_token ) {
    # must have generated an access token via refresh token so revoke the old
    # access token and refresh token (also copy required data if missing)
	my $prev_rt = $obj->db->get_collection( 'refresh_tokens' )->find_one({
      refresh_token => $old_refresh_token,
									     });
 
	my $prev_at = $obj->db->get_collection( 'access_tokens' )->find_one({
	    access_token => $prev_rt->{access_token},
									    });
 
    # access tokens can be revoked, whilst refresh tokens can remain so we
    # need to get the data from the refresh token as the access token may
    # no longer exist at the point that the refresh token is used
	$scope //= $prev_rt->{scope};
	$user_id = $prev_rt->{user_id};
 
    # need to revoke the access token
    $obj->db->get_collection( 'access_tokens' )->delete_one({ access_token => $prev_at->{access_token} });
 
    } else {
	$user_id = $obj->db->get_collection( 'auth_codes' )->find_one({
      auth_code => $auth_code,
								      })->{user_id};
    }
 
    if ( ref( $client ) ) {
	$scope  = $client->{scope};
	$client = $client->{client_id};
    }
 
  # if the client has en existing refresh token we need to revoke it
    $refresh_tokens->delete_one({ client_id => $client, user_id => $user_id });
 
    $access_tokens->insert_one({
    access_token  => $access_token,
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $client,
    user_id       => $user_id,
			   });
 
    $refresh_tokens->insert_one({
    refresh_token => $refresh_token,
    access_token  => $access_token,
    scope         => $scope,
    client_id     => $client,
    user_id       => $user_id,
			    });
 
    return;
};


my $verify_access_token_sub = sub {

    my $args = {@_};

  my ( $c,$access_token,$scopes_ref,$auth_header, $is_refresh_token ) = map { $args->{$_} } qw(mojo_controller access_token scopes auth_header is_refresh_token);

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub called args=', join( ', ', @_ ) );
    }

  $auth_header = '' unless $auth_header;
    
  $is_refresh_token = '' unless $is_refresh_token;

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub called ( $c,$access_token,$scopes_ref,$auth_header, $is_refresh_token ) =', join( ', ', $c, pp( $access_token, $scopes_ref, $auth_header,$is_refresh_token ) ) );
    }

  my $rt = $c->db->get_collection( 'refresh_tokens' )->find_one({ refresh_token => $access_token });

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub ...is_refresh_token ? '.pp( $is_refresh_token ) );
    
  $c->app->log->debug( 'verify_access_token_sub ...is access_token maybe refresh_token ? ', $rt );
    }
    
  if ( $is_refresh_token && $rt ) 
  {
    if ( $scopes_ref ) 
    {
      foreach my $scope ( @{ $scopes_ref // [] } ) 
      {
        if ( ! exists( $rt->{scope}->{$scope} ) or ! $rt->{scope}->{$scope} ) 
	{
          $c->app->log->debug( "OAuth2::Server: Refresh token does not have scope ($scope)" );

          return ( 0,'invalid_grant' );
        }
      }
    }

    return $rt;
  }


    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub ...db ?', $c->db );

  $c->app->log->debug( 'verify_access_token_sub ...db access_tokens ?', $c->db->get_collection( 'access_tokens' ) );
    }

    my $filter = { access_token => $access_token };

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub ...db access_tokens filter ?'.pp( $filter ) );
    }

  my $at = $c->db->get_collection( 'access_tokens' )->find_one( $filter );


    if( $ENV{EXAMPLEDB_DEBUG} )
    {
  $c->app->log->debug( 'verify_access_token_sub ...at ?'.pp( $at ) );
    }

  if( $at ) 
  {
    if ( $at->{expires} <= time ) 
    {
      $c->app->log->debug( "OAuth2::Server: Access token has expired" );
      
      _revoke_access_token( $c,$access_token );
      
      return ( 0,'invalid_grant' );
      
    } 
    elsif( $scopes_ref ) 
    {
      foreach my $scope ( @{ $scopes_ref // [] } ) 
      {
        if ( ! exists( $at->{scope}->{$scope} ) or ! $at->{scope}->{$scope} ) 
	{
          $c->app->log->debug( "OAuth2::Server: Access token does not have scope ($scope)" );

          return ( 0,'invalid_grant' );
        }
      }

    }

    $c->app->log->debug( "OAuth2::Server: Access token is valid" );

    return $at;
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return 0;
};

sub _revoke_access_token {

  my ( $c,$access_token ) = @_;

  $c->db->get_collection( 'access_tokens' )->delete_one({
    access_token => $access_token,  
  });
}


sub as_list
{
    return 
	(
	login_resource_owner      => $resource_owner_logged_in_sub,
	confirm_by_resource_owner => $resource_owner_confirm_scopes_sub,
	
	verify_client             => $verify_client_sub,
	store_auth_code           => $store_auth_code_sub,
	verify_auth_code          => $verify_auth_code_sub,
	store_access_token        => $store_access_token_sub,
	verify_access_token       => $verify_access_token_sub,
	);
}

1;
