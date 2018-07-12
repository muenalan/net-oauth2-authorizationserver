#!/usr/bin/perl

use strict;
use warnings;

use Mojo::Base -strict;

use Test::More;

use Test::Mojo;

use Data::Dump qw(pp);

use Test::Mojo::TxHistory;

my $txhist = Test::Mojo::TxHistory->new( flag_enabled => 0 );



my $ts = Test::Mojo->new('ExampleDB');

$ts->get_ok('/')->status_is(200)->content_like(qr/Welcome/i);

$ts->get_ok('/api/annoy_friends')->status_is(401)->content_like(qr/Unauthorized/i);

$ts->get_ok('/api/post_image')->status_is(401)->content_like(qr/Unauthorized/i);

$ts->get_ok('/api/track_location')->status_is(401)->content_like(qr/You cannot track location/i);

note 'Authorizing via ExampleClient';



{
# Use absolute URL for request with Basic authentication
my $url = $ts->ua->server->url->userinfo('Lee:Pa55w0rd')->path('/oauth/login');

$ts->post_ok($url => form => { username => 'bad', password => 'bad' }) # => json => {limit => 10})
    ->status_is(401)
    ->content_like(qr/Incorrect/);


$ts->post_ok($url => form => { username => 'Lee', password => 'Pa55w0rd' }) # => json => {limit => 10})
   ->status_is(200)
#    ->content_like( qr/access_token/ )
#    ->content_like( qr/refresh_token/ )
    ->content_like(qr/Logged in/);

}

#warn "CONTENT: ", pp( $ts->tx->res->content );






# Customize all transactions (including followed redirects)

note 'USING SERVER URL: ', $ts->ua->server->url;

$ENV{HOST} = $ts->ua->server->url; #'http://127.0.0.1:3000';

note '-----------------------------------------------------------------------------------------------------';

use Path::Class;

use lib qw(../../example_client/lib);

my $tc = Test::Mojo->new('ExampleClient');





#$tc->ua->server( $ts );

# Allow redirects
$tc->ua->max_redirects(10)->connect_timeout(10)->request_timeout(10);

# Switch protocol from HTTP to HTTPS
#$tc->ua->server->url('https');

    $tc->ua->on(

	start => sub {
	
	    my ($ua, $tx) = @_;
	    
	    $tx->req->headers->accept_language('en-US');
	    
	   }

	);


# Should get us to confirm scopes..

{
$tc->get_ok('/auth')->status_is(200);

$txhist->dump;




my $url = $ts->ua->server->url->userinfo('Lee:Pa55w0rd')->path('/oauth/login');


$tc->post_ok($url => form => { username => 'Lee', password => 'Pa55w0rd' }) # => json => {limit => 10})
   ->status_is(200)
   ->content_like( qr/would like to/ )
   ->element_exists('input[type=submit][value]')
    ;
}

#warn "STEP tx: ", pp( $tc->tx );

$txhist->dump( TC => $tc->tx, TS => $ts->tx );


{
    my $url = $tc->tx->req->url;

$tc->post_ok($url => form => { allow => 'Allow' }) # => json => {limit => 10})
   ->status_is(200)
   ->content_like( qr/access_token/ )
    ;

}


$txhist->dump( TC => $tc->tx, TS => $ts->tx );






my $json = $tc->tx->res->json;

warn "JSON RESULT: ", pp( $json );

is( $json->{token_type}, 'Bearer', 'Auth response has Bearer token' );

#  1367  curl -v -k -H "Authorization: Bearer "MTUzMTMzMDA5OC01OTk5OTItMC45NjUzNjA3MDgxNjM3NC05Mkw4UmJrbWdURU5Mdk9iM3dHWW9sMmE5Wkx5SDM="" "http://localhost:3000/api/annoy_friends"
#  1368  curl -v -k -H "Authorization: Bearer "MTUzMTMzMDA5OC01OTk5OTItMC45NjUzNjA3MDgxNjM3NC05Mkw4UmJrbWdURU5Mdk9iM3dHWW9sMmE5Wkx5SDM="" "http://localhost:3000/api/post_image"
#  1369  curl -v -k -H "Authorization: Bearer "MTUzMTMzMDA5OC01OTk5OTItMC45NjUzNjA3MDgxNjM3NC05Mkw4UmJrbWdURU5Mdk9iM3dHWW9sMmE5Wkx5SDM="" "http://localhost:3000/api/track_location"


$ts->get_ok('/api/annoy_friends' => {'Authorization' => 'Bearer '.$json->{access_token} } )->status_is(200)->content_like( qr/Annoyed Friend/i );

#  1371  curl -v -k -H "Authorization: Bearer foo" "http://localhost:3000/api/annoy_friends"

$ts->get_ok('/api/annoy_friends' => {'Authorization' => 'Bearer foo' } )->status_is(401)->content_like( qr/Unauthorized/i );


$txhist->dump( TC => $tc->tx, TS => $ts->tx );


$ts->get_ok('/api/post_image'  => {'Authorization' => 'Bearer '.$json->{access_token} } )->status_is(200)->content_like( qr/Posted Image/i );

$txhist->dump( TC => $tc->tx, TS => $ts->tx );

$ts->get_ok('/api/track_location' => {'Authorization' => 'Bearer '.$json->{access_token} } )->status_is(401)->content_like(qr/You cannot track location/i);

$txhist->dump( TC => $tc->tx, TS => $ts->tx );

#  1380  curl -k -XPOST http://127.0.0.1:3000/oauth/access_token -d "client_id=TrendyNewService&refresh_token=MTUzMTMzMDQ1Ny04MzE5LTAuMDU1MDc4NTg0ODIzOTMxNS1BTXFBMkR5aWh1VlFicHhKSmNhaDVIbUhZWmgwdWk=&grant_type=refresh_token"|json_pp
#  1381  curl -v -k -H "Authorization: Bearer MTUzMTMzMDUzMi02MjQ1NTItMC45MjQ3MTQ2NzA0NzM2NTktR2RENkhHenBibld5bFNaM0dhVW9KM0JhZE1UT1p1" "http://localhost:3000/api/post_image"

done_testing();

# vim: ts=2:sw=2:et
