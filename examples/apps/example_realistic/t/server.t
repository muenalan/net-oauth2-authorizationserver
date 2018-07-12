#!/usr/bin/perl

use strict;
use warnings;

use Mojolicious::Lite;
use FindBin qw/ $Bin /;

use lib qw(lib);

use Net::OAuth2::AuthorizationServer::Callbacks::ExampleRealistic;

chdir( $Bin );

app->config(
  hypnotoad => {
    listen => [ 'https://*:3000' ]
  }
);


plugin 'OAuth2::Server' => {
  auth_code_ttl             => 300,
  access_token_ttl          => 600,

  Net::OAuth2::AuthorizationServer::Callbacks::ExampleRealistic->as_list
    
#   login_resource_owner      => $resource_owner_logged_in_sub,
#   confirm_by_resource_owner => $resource_owner_confirm_scopes_sub,

#   verify_client             => $verify_client_sub,
#   store_auth_code           => $store_auth_code_sub,
#   verify_auth_code          => $verify_auth_code_sub,
#   store_access_token        => $store_access_token_sub,
#   verify_access_token       => $verify_access_token_sub,
    
};

group {
  # /api - must be authorized
  under '/api' => sub {
    my ( $c ) = @_;
    if ( my $auth_info = $c->oauth ) {
      $c->stash( oauth_info => $auth_info ); 
      return 1;
    }
    $c->render( status => 401, text => 'Unauthorized' );
    return undef;
  };

  any '/annoy_friends' => sub {
    my ( $c ) = @_;
    my $user_id = $c->stash( 'oauth_info' )->{user_id};
    $c->render( text => "$user_id Annoyed Friends" );
  };
  any '/post_image'    => sub {
    my ( $c ) = @_;
    my $user_id = $c->stash( 'oauth_info' )->{user_id};
    $c->render( text => "$user_id Posted Image" );
  };
};

any '/api/track_location' => sub {
  my ( $c ) = @_;
  my $auth_info = $c->oauth( 'track_location' )
      || return $c->render( status => 401, text => 'You cannot track location' );
  $c->render( text => "Target acquired: " . $auth_info->{user_id} );
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Welcome to Overly Attached Social Network" );
};

get '/oauth/login' => sub {
  my ( $c ) = @_;

  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  }

  if ( $c->session( 'logged_in' ) ) {
    return $c->render( text => 'Logged in!' )
  } else {
    return $c->render( error  => undef );
  }
};

any '/logout' => sub {
  my ( $c ) = @_;
  $c->session( expires => 1 );
  $c->redirect_to( '/' );
};

post '/oauth/login' => sub {
  my ( $c ) = @_;

  my $username = $c->param('username');
  my $password = $c->param('password');

  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  }

  if ( $username eq 'Lee' and $password eq 'P@55w0rd' ) {
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
};

any '/oauth/confirm_scopes' => sub {
  my ( $c ) = @_;

  # in theory we should only ever get here via a redirect from
  # a login (that was itself redirected to from /oauth/authorize
  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  } else {
    return $c->render(
      text => "Got to /confirm_scopes without redirect_after_login?"
    );
  }

  if ( $c->req->method eq 'POST' ) {

    my $client_id = $c->flash( 'client_id' );
    my $allow     = $c->param( 'allow' );

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
};

app->secrets( ['Setec Astronomy'] );
app->sessions->cookie_name( 'oauth2_server' );
app->start;

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
  username: Lee<br />
  password: P@55w0rd
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
