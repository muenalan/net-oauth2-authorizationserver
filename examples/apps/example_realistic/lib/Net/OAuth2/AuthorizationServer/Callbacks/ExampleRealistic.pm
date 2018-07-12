package Net::OAuth2::AuthorizationServer::Callbacks::ExampleRealistic;

use strict;

use warnings;

use Mojo::JSON qw/ decode_json encode_json /;

# N.B. this uses a little JSON file, which would not scale - in reality
# you should be using a database of some sort

my $storage_file = "oauth2_db.json";

sub save_oauth2_data {
  my ( $config ) = @_;
  my $json = encode_json( $config );
  open( my $fh,'>',$storage_file )
    || die "Couldn't open $storage_file for write: $!";
  print $fh $json;
  close( $fh );
  return 1;
}

sub load_oauth2_data {
  open( my $fh,'<',$storage_file )
    || die "Couldn't open $storage_file for read: $!";
  my $json;
  while ( my $line = <$fh> ) {
    $json .= $line;
  }
  close( $fh );
  return decode_json( $json );
}



my $resource_owner_logged_in_sub = sub {
  my ( $c ) = @_;

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

my $resource_owner_confirm_scopes_sub = sub {
  my ( $c,$client_id,$scopes_ref ) = @_;

  my $is_allowed = $c->flash( "oauth_${client_id}" );

  # if user hasn't yet allowed the client access, or if they denied
  # access last time, we check [again] with the user for access
  if ( ! $is_allowed ) {
    $c->flash( client_id => $client_id );
    $c->flash( scopes    => $scopes_ref );

    my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
    $c->flash( 'redirect_after_login' => $uri );
    $c->redirect_to( '/oauth/confirm_scopes' );
  }

  return ( $is_allowed,undef,$scopes_ref );
};

my $verify_client_sub = sub {
  my ( $c,$client_id,$scopes_ref ) = @_;

  my $oauth2_data = load_oauth2_data();

  if ( my $client = $oauth2_data->{clients}{$client_id} ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {

        if ( ! exists( $client->{scopes}{$scope} ) ) {
          $c->app->log->debug( "OAuth2::Server: Client lacks scope ($scope)" );
          return ( 0,'invalid_scope' );
        } elsif ( ! $client->{scopes}{$scope} ) {
          $c->app->log->debug( "OAuth2::Server: Client cannot scope ($scope)" );
          return ( 0,'access_denied' );
        }
      }

      return ( 1 );
  }

  $c->app->log->debug( "OAuth2::Server: Client ($client_id) does not exist" );
  return ( 0,'unauthorized_client' );
};

my $store_auth_code_sub = sub {
  my ( $c,$auth_code,$client_id,$expires_in,$uri,@scopes ) = @_;

  my $oauth2_data = load_oauth2_data();

  my $user_id = $c->session( 'user_id' );

  $oauth2_data->{auth_codes}{$auth_code} = {
    client_id     => $client_id,
    user_id       => $user_id,
    expires       => time + $expires_in,
    redirect_uri  => $uri,
    scope         => { map { $_ => 1 } @scopes },
  };

  $oauth2_data->{auth_codes_by_client}{$client_id} = $auth_code;

  save_oauth2_data( $oauth2_data );

  return;
};

my $verify_auth_code_sub = sub {
  my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

  my $oauth2_data = load_oauth2_data();

  my $client = $oauth2_data->{clients}{$client_id}
    || return ( 0,'unauthorized_client' );

  return ( 0,'invalid_grant' )
    if ( $client_secret ne $client->{client_secret} );

  if (
    ! exists( $oauth2_data->{auth_codes}{$auth_code} )
    or ! exists( $oauth2_data->{clients}{$client_id} )
    or ( $client_secret ne $oauth2_data->{clients}{$client_id}{client_secret} )
    or $oauth2_data->{auth_codes}{$auth_code}{access_token}
    or ( $uri && $oauth2_data->{auth_codes}{$auth_code}{redirect_uri} ne $uri )
    or ( $oauth2_data->{auth_codes}{$auth_code}{expires} <= time )
  ) {

    if ( $oauth2_data->{verified_auth_codes}{$auth_code} ) {
      # the auth code has been used before - we must revoke the auth code
      # and access tokens
      my $auth_code_data = delete( $oauth2_data->{auth_codes}{$auth_code} );
      $oauth2_data = _revoke_access_token( $c,$auth_code_data->{access_token} );
      save_oauth2_data( $oauth2_data );
    }

    return ( 0,'invalid_grant' );
  }

  # scopes are those that were requested in the authorization request, not
  # those stored in the client (i.e. what the auth request restriced scopes
  # to and not everything the client is capable of)
  my $scope = $oauth2_data->{auth_codes}{$auth_code}{scope};
  my $user_id = $oauth2_data->{auth_codes}{$auth_code}{user_id};

  $oauth2_data->{verified_auth_codes}{$auth_code} = 1;

  save_oauth2_data( $oauth2_data );

  return ( $client_id,undef,$scope,$user_id );
};

my $store_access_token_sub = sub {
  my (
    $c,$client,$auth_code,$access_token,$refresh_token,
    $expires_in,$scope,$old_refresh_token
  ) = @_;

  my $oauth2_data = load_oauth2_data();
  my $user_id;

  if ( ! defined( $auth_code ) && $old_refresh_token ) {
    # must have generated an access token via a refresh token so revoke the old
    # access token and refresh token and update the oauth2_data->{auth_codes}
    # hash to store the new one (also copy across scopes if missing)
    $auth_code = $oauth2_data->{refresh_tokens}{$old_refresh_token}{auth_code};

    my $prev_access_token
      = $oauth2_data->{refresh_tokens}{$old_refresh_token}{access_token};

    # access tokens can be revoked, whilst refresh tokens can remain so we
    # need to get the data from the refresh token as the access token may
    # no longer exist at the point that the refresh token is used
    $scope //= $oauth2_data->{refresh_tokens}{$old_refresh_token}{scope};
    $user_id = $oauth2_data->{refresh_tokens}{$old_refresh_token}{user_id};

    $c->app->log->debug( "OAuth2::Server: Revoking old access tokens (refresh)" );
    $oauth2_data = _revoke_access_token( $c,$prev_access_token );

  } else {
    $user_id = $oauth2_data->{auth_codes}{$auth_code}{user_id};
  }

  if ( ref( $client ) ) {
    $scope  = $client->{scope};
    $client = $client->{client_id};
  }

  # if the client has en existing refresh token we need to revoke it
  delete( $oauth2_data->{refresh_tokens}{$old_refresh_token} )
    if $old_refresh_token;

  $oauth2_data->{access_tokens}{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $client,
    user_id       => $user_id,
  };

  $oauth2_data->{refresh_tokens}{$refresh_token} = {
    scope         => $scope,
    client_id     => $client,
    user_id       => $user_id,
    auth_code     => $auth_code,
    access_token  => $access_token,
  };

  $oauth2_data->{auth_codes}{$auth_code}{access_token} = $access_token;

  $oauth2_data->{refresh_tokens_by_client}{$client} = $refresh_token;

  save_oauth2_data( $oauth2_data );
  return;
};

my $verify_access_token_sub = sub {
  my ( $c,$access_token,$scopes_ref,$is_refresh_token ) = @_;

  my $oauth2_data = load_oauth2_data();

  if (
    $is_refresh_token
	&& exists( $oauth2_data->{refresh_tokens}{$access_token} )
  ) {

    if ( $scopes_ref ) {
      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $oauth2_data->{refresh_tokens}{$access_token}{scope}{$scope} )
          or ! $oauth2_data->{refresh_tokens}{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Refresh token does not have scope ($scope)" );
          return ( 0,'invalid_grant' );
        }
      }
    }

    return $oauth2_data->{refresh_tokens}{$access_token};
  }
  if ( exists( $oauth2_data->{access_tokens}{$access_token} ) ) {

    if ( $oauth2_data->{access_tokens}{$access_token}{expires} <= time ) {
      $c->app->log->debug( "OAuth2::Server: Access token has expired" );
      $oauth2_data = _revoke_access_token( $c,$access_token );
      return ( 0,'invalid_grant' );
    } elsif ( $scopes_ref ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $oauth2_data->{access_tokens}{$access_token}{scope}{$scope} )
          or ! $oauth2_data->{access_tokens}{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Access token does not have scope ($scope)" );
          return ( 0,'invalid_grant' );
        }
      }

    }

    $c->app->log->debug( "OAuth2::Server: Access token is valid" );
    return $oauth2_data->{access_tokens}{$access_token};
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return 0;
};

sub _revoke_access_token {
  my ( $c,$access_token ) = @_;

  my $oauth2_data = load_oauth2_data();

  delete( $oauth2_data->{access_tokens}{$access_token} );

  save_oauth2_data( $oauth2_data );
  return $oauth2_data;
}


#my $mixin = { Net::OAuth2::AuthorizationServer::Example::CallbacksDB->as_list };

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
