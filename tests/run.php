<?php
/**
 * Tests, with no dependencies: php tests/run.php
 */

use AccessNow\SpamEater\Content;
use AccessNow\SpamEater\Guard;
use AccessNow\SpamEater\Ip;

require dirname( __DIR__ ) . '/autoload.php';

$failures = 0;
$passes   = 0;

function ok( $condition, $label ) {
	global $failures, $passes;
	if ( $condition ) {
		$passes++;
	} else {
		$failures++;
		echo "FAIL: $label\n";
	}
}

function same( $expected, $actual, $label ) {
	ok( $expected === $actual, $label . ' (expected ' . var_export( $expected, true ) . ', got ' . var_export( $actual, true ) . ')' );
}

$secret  = str_repeat( 'k', 40 );
$storage = sys_get_temp_dir() . '/spam-eater-test-' . getmypid();
$now     = 1790000000;
$clock   = function () use ( &$now ) {
	return $now;
};
$server  = array( 'REMOTE_ADDR' => '203.0.113.7' );

function guard( array $extra = array() ) {
	global $secret, $storage, $clock;
	return new Guard( array_merge( array( 'secret' => $secret, 'storage' => $storage, 'clock' => $clock ), $extra ) );
}

/** What a real browser sends: the form loaded, tokens filled in, $wait seconds later. */
function human( Guard $g, $wait = 10, array $fields = array() ) {
	global $now;
	$t = $g->tokens();
	if ( ! isset( $t['act'] ) ) { // With a refresh_url the script asks for the visitor's own.
		$t = array_merge( $t, $g->issueAct( $t['ts'], '203.0.113.7' ) );
	}
	$now += $wait;
	return array_merge(
		array(
			'name'           => 'Jo',
			'message'        => 'Hello there',
			$g->fieldName()  => '',
			'se_js'          => $t['js'],
			'se_ts'          => $t['ts'],
			'se_act'         => $t['act'],
		),
		$fields
	);
}

// --- Setup -----------------------------------------------------------------

try {
	new Guard( array( 'secret' => 'short' ) );
	ok( false, 'a short secret is refused' );
} catch ( InvalidArgumentException $e ) {
	ok( true, 'a short secret is refused' );
}

$g = guard();
ok( (bool) preg_match( '/^se_[0-9a-f]{8}$/', $g->fieldName() ), 'field name is se_ + 8 hex' );
same( $g->fieldName(), guard()->fieldName(), 'field name is stable for a secret' );
ok( $g->fieldName() !== guard( array( 'secret' => str_repeat( 'z', 40 ) ) )->fieldName(), 'field name differs per secret' );

$html = $g->field();
ok( false !== strpos( $html, 'name="' . $g->fieldName() . '"' ), 'field() prints the honeypot' );
ok( false !== strpos( $html, 'class="se-ts" value="' . $now . ':' ), 'field() prints a signed timestamp' );
ok( false === strpos( $html, 'data-refresh' ), 'no refresh URL unless configured' );
$html = guard( array( 'refresh_url' => '/t.php?a="b"' ) )->field( 'contact' );
ok( false !== strpos( $html, 'data-refresh="/t.php?a=&quot;b&quot;"' ), 'refresh URL is escaped' );
ok( false !== strpos( $html, 'name="contact[se_js]"' ), 'field( group ) nests the names' );

$s = $g->script();
ok( 0 === strpos( $s, '<script>' ) && false !== strpos( $s, 'SpamEater' ), 'script() inlines the script' );
same( '', $g->script(), 'script() prints only once' );
ok( false !== strpos( guard()->script( 'abc' ), '<script nonce="abc">' ), 'script() takes a CSP nonce' );

// --- A real submission passes ------------------------------------------------

$g = guard();
same( false, $g->check( human( $g ), 'full', $server ), 'a real submission passes' );
same( '', $g->failCode(), 'no code when it passes' );

// --- Each failure, with its code ----------------------------------------------

$cases = array(
	'filled honeypot'      => array( 'SE-B1', function ( $p, $g ) { $p[ $g->fieldName() ] = 'http://spam'; return $p; } ),
	'honeypot as an array' => array( 'SE-B1', function ( $p, $g ) { $p[ $g->fieldName() ] = array( 'x' ); return $p; } ),
	'no JavaScript'        => array( 'SE-C2', function ( $p ) { $p['se_js'] = ''; return $p; } ),
	'forged JS token'      => array( 'SE-C2', function ( $p ) { $p['se_js'] = str_repeat( 'a', 32 ); return $p; } ),
	'tampered timestamp'   => array( 'SE-D3', function ( $p ) { $p['se_ts'] = '1:abc'; return $p; } ),
	'missing timestamp'    => array( 'SE-D3', function ( $p ) { unset( $p['se_ts'] ); return $p; } ),
	'no interaction'       => array( 'SE-F4', function ( $p ) { $p['se_act'] = ''; return $p; } ),
);
foreach ( $cases as $label => $case ) {
	$g = guard( array( 'block_after' => 0 ) );
	same( true, $g->check( $case[1]( human( $g ), $g ), 'full', $server ), "$label is spam" );
	same( $case[0], $g->failCode(), "$label code" );
}

$g = guard();
same( true, $g->check( human( $g, 1 ), 'full', $server ), 'sent after 1 second is spam' );
same( 'SE-E3', $g->failCode(), 'too fast code' );
same( 'too_fast', $g->reason(), 'too fast reason' );

$g = guard( array( 'min_seconds' => 0 ) );
same( false, $g->check( human( $g, 1 ), 'full', $server ), 'min_seconds 0 allows a quick send' );

$g = guard();
same( true, $g->check( human( $g, 172800 + 5 ), 'full', $server ), 'a two-day-old page is spam' );
same( 'SE-C2', $g->failCode(), 'its JS token has rotated out first' );

$g = guard();
same( false, $g->check( human( $g, 86400 + 5 ), 'full', $server ), 'a one-day-old page still passes' );

// --- Contexts -----------------------------------------------------------------

$g = guard();
same( false, $g->check( array( $g->fieldName() => '' ), 'login', $server ), 'login: honeypot only' );
same( true, $g->check( array( $g->fieldName() => 'x' ), 'login', $server ), 'login: filled honeypot is spam' );
same( false, $g->check( array( $g->fieldName() => '', 'email' => 'a@b.com' ), 'basic', $server ), 'basic: no tokens needed' );

// --- Repeat bots are blocked, and only for a filled honeypot -------------------

@array_map( 'unlink', glob( $storage . '/*.json' ) ?: array() );
$bot = array( 'REMOTE_ADDR' => '198.51.100.9' );
for ( $i = 1; $i <= 6; $i++ ) {
	$g = guard( array( 'min_seconds' => 0 ) );
	$g->check( array( $g->fieldName() => 'spam' ), 'full', $bot );
}
$g = guard();
ok( $g->isBlocked( '198.51.100.9' ), 'blocked after 5 honeypot hits' );
same( true, $g->check( human( $g ), 'full', $bot ), 'a blocked address is refused even with good tokens' );
same( 'SE-A0', $g->failCode(), 'blocked code' );
same( false, $g->check( array( $g->fieldName() => '' ), 'login', $bot ), 'a blocked address can still log in' );
ok( ! $g->isBlocked( '203.0.113.7' ), 'other addresses are not blocked' );
$stored = (string) file_get_contents( $storage . '/blocked.json' );
ok( false === strpos( $stored, '198.51.100' ), 'raw addresses are never stored' );

$now += 25 * 3600;
ok( ! guard()->isBlocked( '198.51.100.9' ), 'the block expires after 24 hours' );

for ( $i = 1; $i <= 5; $i++ ) {
	$g = guard( array( 'min_seconds' => 0 ) );
	$g->check( array( $g->fieldName() => 'spam' ), 'full', $bot );
}
ok( guard()->isBlocked( '198.51.100.9' ), 'blocked again' );
guard()->unblock( '198.51.100.9' );
ok( ! guard()->isBlocked( '198.51.100.9' ), 'unblock() removes it' );

for ( $i = 1; $i <= 6; $i++ ) {
	$g = guard();
	$g->check( human( $g, 1 ), 'full', $bot );
}
ok( ! guard()->isBlocked( '198.51.100.9' ), 'other failures never count towards a block' );

$g = guard( array( 'storage' => null ) );
$g->check( array( $g->fieldName() => 'spam' ), 'full', $bot );
ok( ! $g->isBlocked( '198.51.100.9' ), 'no storage: no blocking, no errors' );

// --- Allow and block lists, proxies ---------------------------------------------

$g = guard( array( 'allow' => array( '203.0.113.0/24' ) ) );
same( false, $g->check( array( $g->fieldName() => 'x' ), 'full', $server ), 'Always allow skips every check' );
$g = guard( array( 'block' => array( '2001:db8::/32' ) ) );
same( true, $g->check( human( $g ), 'full', array( 'REMOTE_ADDR' => '2001:db8::5' ) ), 'Always block (IPv6 range)' );
same( 'SE-H0', $g->failCode(), 'Always block code' );

$proxied = array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '192.0.2.44, 10.0.0.1' );
same( '10.0.0.2', Ip::client( $proxied ), 'X-Forwarded-For ignored without trusted proxies' );
same( '192.0.2.44', Ip::client( $proxied, array( '10.0.0.0/8' ) ), 'X-Forwarded-For read through trusted proxies' );
same( '192.0.2.44', Ip::client( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 192.0.2.44' ), array( '10.0.0.0/8' ) ), 'a forged left-hand entry is ignored' );
same( '192.0.2.1', Ip::normalise( '192.0.2.1:8080' ), 'port stripped' );
same( '2001:db8::1', Ip::normalise( '[2001:DB8::1]:443' ), 'IPv6 brackets stripped and lower-cased' );
same( '', Ip::normalise( 'nonsense' ), 'invalid address' );
same( '192.0.2.0', Ip::anonymise( '192.0.2.77' ), 'IPv4 anonymised' );
same( '2001:db8:1::', Ip::anonymise( '2001:db8:1:2:3:4:5:6' ), 'IPv6 anonymised' );
ok( Ip::inRange( '192.0.2.130', '192.0.2.128/25' ) && ! Ip::inRange( '192.0.2.127', '192.0.2.128/25' ), 'CIDR /25' );

// --- Content ------------------------------------------------------------------

$g = guard( array( 'words' => "# comment\nviagra\nseo services\n/https?:\\/\\/\\S+\\.ru\\b/i" ) );
same( true, $g->check( human( $g, 10, array( 'message' => 'Cheap VIAGRA now' ) ), 'full', $server ), 'a blocked word' );
same( 'SE-K5', $g->failCode(), 'blocked word code' );
$g = guard( array( 'words' => "seo services" ) );
same( true, $g->check( human( $g, 10, array( 'message' => "We offer SEO\n services" ) ), 'full', $server ), 'phrases match across whitespace' );
$g = guard( array( 'words' => "cialis" ) );
same( false, $g->check( human( $g, 10, array( 'message' => 'specialist' ) ), 'full', $server ), 'whole words only' );
$g = guard( array( 'words' => "/https?:\\/\\/\\S+\\.ru\\b/i" ) );
same( true, $g->check( human( $g, 10, array( 'message' => 'see http://x.example.ru now' ) ), 'full', $server ), 'a regex rule' );
$g = guard( array( 'words' => array( 'viagra' ) ) );
same( false, $g->check( human( $g, 10, array( 'password' => 'viagra' ) ), 'full', $server ), 'password fields are never checked' );
same( array(), Content::compile( "/unclosed(/\n" ), 'an invalid regex is skipped' );

$g = guard( array( 'block_disposable' => true ) );
same( true, $g->check( human( $g, 10, array( 'email' => 'x@mailinator.com' ) ), 'full', $server ), 'a throwaway email' );
same( 'SE-M5', $g->failCode(), 'throwaway email code' );
$g = guard( array( 'block_disposable' => true ) );
same( true, $g->check( human( $g, 10, array( 'email' => 'x@sub.mailinator.com' ) ), 'full', $server ), 'a subdomain of a throwaway domain' );
$g = guard( array( 'block_disposable' => true ) );
same( false, $g->check( human( $g, 10, array( 'email' => 'jo@gmail.com' ) ), 'full', $server ), 'a normal email passes' );
$g = guard();
same( false, $g->check( human( $g, 10, array( 'email' => 'x@mailinator.com' ) ), 'full', $server ), 'throwaway check is off by default' );

$c = new Content( '', function () {
	return array( 'throwaway.test' => true );
} );
ok( $c->isDisposableDomain( 'a.throwaway.test' ) && ! $c->isDisposableDomain( 'mailinator.com' ), 'the domain list can come from a function' );
same( 1, $c->countDomains(), 'countDomains()' );
same( array( 'ok(' ), Content::collect( array( 'v' => "ok\xC3\x28" ) ), 'invalid UTF-8 is dropped' );
same( array( 'X' ), Content::collect( array( 'v' => 'x', 'my_csrf' => 'y' ), array(), 'strtoupper' ), 'collect() takes a cleaner and skips CSRF fields' );

// --- Tokens -------------------------------------------------------------------

$t     = new \AccessNow\SpamEater\Tokens( $secret, 7200, $clock );
$token = $t->token( 'js' );
ok( $t->verify( 'js', $token ) && ! $t->verify( 'act', $token ), 'a token is tied to its purpose' );
$now += 3600;
ok( $t->verify( 'js', $token ), 'the previous tick is still accepted' );
$now += 3600;
ok( ! $t->verify( 'js', $token ), 'two ticks later it is not' );
same( 3600, ( new \AccessNow\SpamEater\Tokens( $secret, 60 ) )->lifetime(), 'lifetime is at least an hour' );
same( 5, ( function () use ( $t, &$now ) { $s = $t->stamp(); $now += 5; return $t->verifyStamp( $s ); } )(), 'verifyStamp() gives the age' );
same( null, $t->verifyStamp( '12:' ), 'an empty signature is invalid' );

// --- Interaction tokens issued per visitor (refresh_url) -------------------------

$url = array( 'refresh_url' => '/tokens.php', 'block_after' => 0 );
$g   = guard( $url );
$t   = $g->tokens();
ok( ! isset( $t['act'] ) && false === strpos( $g->field(), 'data-act' ), 'with refresh_url, the page has no interaction token' );
ok( isset( guard()->tokens()['act'] ) && false !== strpos( guard()->field(), 'data-act' ), 'without one, it still does' );
same( false, $g->check( human( $g ), 'full', $server ), 'with refresh_url, a real submission passes' );

$g    = guard( $url );
$p    = human( $g );
$p2   = human( $g );
$p['se_act'] = $p2['se_act'];
same( true, $g->check( $p, 'full', $server ), "another form's interaction token is spam" );
same( 'SE-F4', $g->failCode(), 'its code' );

$g = guard( $url );
$p = human( $g );
$p['se_act'] = ( new \AccessNow\SpamEater\Tokens( $secret ) )->token( 'act' );
same( true, $g->check( $p, 'full', $server ), 'the old page-wide interaction token is spam' );

$g = guard( $url );
$p = human( $g );
for ( $i = 1; $i <= 5; $i++ ) {
	same( false, $g->check( $p, 'full', $server ), "one interaction token passes use $i" );
}
same( true, $g->check( $p, 'full', $server ), 'and is spam on use 6' );
same( 'SE-R4', $g->failCode(), 'reused token code' );
same( false, guard( $url + array( 'token_uses' => 0 ) )->check( $p, 'full', $server ), 'token_uses 0: no limit' );

$g     = guard( $url + array( 'act_per_hour' => 3 ) );
$stamp = $g->tokens()['ts'];
$got   = array();
for ( $i = 1; $i <= 4; $i++ ) {
	$got[] = null !== $g->issueAct( $stamp, '198.51.100.9' );
}
same( array( true, true, true, false ), $got, 'act_per_hour limits tokens per address' );
ok( null !== $g->issueAct( $stamp, '198.51.100.10' ), 'other addresses are unaffected' );
$now += 3600;
ok( null !== $g->issueAct( $stamp, '198.51.100.9' ), 'the limit resets after an hour' );

$g     = guard( $url );
$old   = $g->tokens()['ts'];
$now  += 172800 + 10;
$a     = $g->issueAct( $old, '203.0.113.7' );
ok( $a['ts'] !== $old && null !== ( new \AccessNow\SpamEater\Tokens( $secret, 172800, $clock ) )->verifyStamp( $a['ts'] ), 'an expired timestamp gets a fresh one' );
$a = $g->issueAct( 'nonsense', '203.0.113.7' );
same( 0, ( new \AccessNow\SpamEater\Tokens( $secret, 172800, $clock ) )->verifyStamp( $a['ts'] ), 'so does an invalid one' );

$g = guard( $url );
ob_start();
$g->sendTokens( array( 'se_ts' => $g->tokens()['ts'] ), array( 'REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '203.0.113.7' ) );
$json = json_decode( (string) ob_get_clean(), true );
ok( isset( $json['ts'], $json['act'] ) && ! isset( $json['js'] ), 'sendTokens() answers a POST with ts and act' );
ob_start();
$g->sendTokens( null, array( 'REQUEST_METHOD' => 'GET' ) );
$json = json_decode( (string) ob_get_clean(), true );
ok( isset( $json['js'], $json['ts'] ) && ! isset( $json['act'] ), 'and a GET with js and ts, no act' );

$t  = new \AccessNow\SpamEater\Tokens( $secret );
$s1 = $t->stamp();
$a1 = $t->actFor( $s1 );
ok( (bool) preg_match( '/^[0-9a-f]{16}\.[0-9a-f]{32}$/', $a1 ) && $a1 !== $t->actFor( $s1 ), 'actFor() is id.signature, different each time' );
same( substr( $a1, 0, 16 ), $t->verifyAct( $s1, $a1 ), 'verifyAct() gives the id' );
same( null, $t->verifyAct( $s1 . 'x', $a1 ), 'verifyAct() refuses another stamp' );
same( null, $t->verifyAct( $s1, array( $a1 ) ), 'verifyAct() refuses an array' );

// --- on_block -----------------------------------------------------------------

$seen = array();
$g    = guard( array( 'block_after' => 0, 'on_block' => function ( $reason, $code, $ip ) use ( &$seen ) { $seen = array( $reason, $code, $ip ); } ) );
$g->check( array( $g->fieldName() => 'x' ), 'full', $server );
same( array( 'filled_honeypot', 'SE-B1', '203.0.113.0' ), $seen, 'on_block gets reason, code and an anonymised address' );

// --- Done ---------------------------------------------------------------------

@array_map( 'unlink', glob( $storage . '/*.json' ) ?: array() );
@rmdir( $storage );

echo $passes . ' passed, ' . $failures . " failed\n";
exit( $failures > 0 ? 1 : 0 );
