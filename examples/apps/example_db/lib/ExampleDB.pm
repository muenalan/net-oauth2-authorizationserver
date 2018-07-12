package ExampleDB;

use Mojo::Base 'Mojolicious';

use strict;

use warnings;

use Mojo::JSON qw/ decode_json encode_json /;

use MongoDB;

use FindBin qw/ $Bin /;

use lib qw(lib);

use Data::Dump qw(pp);

use Net::OAuth2::AuthorizationServer::Callbacks::ExampleDB;








# This method will run once at server start
sub startup 
{
  my $self = shift;

  # Load configuration from hash returned by "my_app.conf"
  my $config = $self->plugin('Config');

#  $self->plugin('PODRenderer') if $config->{perldoc};

  # Router
  my $r = $self->routes;

  # Normal route to controller
#  $r->get('/')->to('example#welcome');



#!/usr/bin/perl


chdir( $Bin );

my $client = MongoDB::MongoClient->new(

  host           => 'localhost',
  port           => 27017,
  auto_reconnect => 1,

);

{
  my $db = $client->get_database( 'oauth2' );

  my $clients = $db->get_collection( 'clients' );

  if ( ! $clients->find_one({ client_id => 'TrendyNewService' }) ) 
  {
    $clients->insert_one({
      client_id     => "TrendyNewService",
      client_secret => "boo",
      scopes => {
        post_images    => 1,
        track_location => 1,
        annoy_friends  => 1,
        download_data  => 0,
      }
    });
  }
}

$self->config(

  hypnotoad => {

    listen => [ 'https://*:3000' ]

  }

);

$self->helper( 
    
    db => sub 
    {
	my $db = $client->get_database( 'oauth2' );
	
	return $db;
    }
);


$self->plugin( 

    'OAuth2::Server' => 
    {
	auth_code_ttl             => 300,
	
	access_token_ttl          => 600,
	
	Net::OAuth2::AuthorizationServer::Callbacks::ExampleDB->as_list
    }
);



# /api - must be authorized
my $r_api = $r->under(
    
    '/api' => sub 
    {
	my ( $c ) = @_;

	$c->app->log->debug( "api/ group access tried. Check oauth=", pp( $c->oauth ) );
	
	if ( my $auth_info = $c->oauth ) {
	    $c->stash( oauth_info => $auth_info ); 
	    
	    $c->app->log->debug( "api/ group access oauth found. Pass.." );
	    
	    return 1;
	}

	$c->app->log->debug( "api/ group access oauth not found" );
	
	$c->render( status => 401, text => 'Unauthorized' );

	return undef;
    }

);

$r_api->any(

    '/annoy_friends' => sub 
    {
	my ( $c ) = @_;

	my $user_id = $c->stash( 'oauth_info' )->{user_id};

	$c->render( text => "$user_id Annoyed Friends" );
    }

);

$r_api->any(

    '/post_image'    => sub 
    {
	my ( $c ) = @_;
	my $user_id = $c->stash( 'oauth_info' )->{user_id};
	$c->render( text => "$user_id Posted Image" );
    }

);






$r->any(

    '/api/track_location' => sub
    {
	my ( $c ) = @_;
	my $auth_info = $c->oauth( 'track_location' )
	    || return $c->render( status => 401, text => 'You cannot track location' );
	$c->render( text => "Target acquired: " . $auth_info->{user_id} );
    }

    
);





$r->get( 

    '/' => sub 
    {
	my ( $c ) = @_;
	$c->render( text => "Welcome to Overly Attached Social Network" );
    }
   
);






$r->get( 

    '/oauth/login' => sub 
    {
	my ( $c ) = @_;
	
	if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
	    $c->flash( 'redirect_after_login' => $redirect_uri );
	}
	
	if ( $c->session( 'logged_in' ) ) {
	    return $c->render( text => 'Logged in!' )
	} else {
	    return $c->render( error  => undef );
    }

    }
);






$r->any( 

    '/logout' => sub 
    {
	my ( $c ) = @_;
	$c->session( expires => 1 );
	$c->redirect_to( '/' );
    } 

    );






$r->post( 

    '/oauth/login' => sub 
    {
	my ( $c ) = @_;
	
	my $username = $c->param('username');
	my $password = $c->param('password');
	
	if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
	    $c->flash( 'redirect_after_login' => $redirect_uri );
	}
	
	if ( $username eq 'Lee' and $password eq 'Pa55w0rd' ) {
	    $c->session( logged_in => 1 );
	    $c->session( user_id   => $username );
	    if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
		return $c->redirect_to( $redirect_uri );
	    } else {
		return $c->render( text => 'Logged in!' )
	    }
	} else {
	    return $c->render(
		status => 401,
		error  => 'Incorrect username/password',
		);
	}
    }
    
);






$r->any(

    '/oauth/confirm_scopes' => sub
    {
	my ( $c ) = @_;
	
	# in theory we should only ever get here via a redirect from
	# a login (that was itself redirected to from /oauth/authorize
	if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) )
	{
	    $c->flash( 'redirect_after_login' => $redirect_uri );
	}
	else
	{
	    return $c->render(
		text => "Got to /confirm_scopes without redirect_after_login?"
		);
	    
	}
	
	if ( $c->req->method eq 'POST' )
	{
	    my $client_id = $c->flash( 'client_id' );
	    my $allow     = $c->param( 'allow' );

    if( $ENV{EXAMPLEDB_DEBUG} )
    {
	    $c->app->log->debug( "confirm_scopes POST received with param allow=", $allow );
    }
	    
	    $c->flash( "oauth_${client_id}" => ( $allow eq 'Allow' ) ? 1 : 0 );
	    
	    if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
		return $c->redirect_to( $redirect_uri );
	    }
	    
	} else {
	    $c->flash( client_id => $c->flash( 'client_id' ) );
	    return $c->render(
		client_id => $c->flash( 'client_id' ),
		scopes    => $c->flash( 'scopes' ),
		);
	}
    }
    
 );
    





$self->secrets( ['Setec Astronomy'] );






$self->sessions->cookie_name( 'oauth2_server' );

}

1;

#$self->start;

# vim: ts=2:sw=2:et

__DATA__
@@ layouts/default.html.ep
<!doctype html><html>
  <head><title>Overly Attached Social Network</title></head>
  <body><h3>Welcome to Overly Attached Social Network</h3><%== content %></body>
</html>

@@ oauthlogin.html.ep
% layout 'default';
% if ( $error ) {
<b><%= $error %></b>
% }
<p>
  username: Lee<br/>
  password: Pa55w0rd
</p>
%= form_for '/oauth/login' => (method => 'POST') => begin
  %= label_for username => 'Username'
  %= text_field 'username'

  %= label_for password => 'Password'
  %= password_field 'password'

  %= submit_button 'Log me in', class => 'btn'
% end

@@ oauthconfirm_scopes.html.ep
% layout 'default';
%= form_for 'confirm_scopes' => (method => 'POST') => begin
  <%= $client_id %> would like to be able to perform the following on your behalf:<ul>
% for my $scope ( @{ $scopes } ) {
  <li><%= $scope %></li>
% }
</ul>
  %= submit_button 'Allow', class => 'btn', name => 'allow'
  %= submit_button 'Deny', class => 'btn', name => 'allow'
% end

