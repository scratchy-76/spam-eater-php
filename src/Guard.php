<?php
/**
 * Spam Eater: stops form spam without CAPTCHAs, on your own server.
 *
 *     $guard = new Guard( array( 'secret' => 'a long random string', 'storage' => '/path/outside/web/root' ) );
 *     echo $guard->field();          // inside the <form>
 *     echo $guard->script();         // once per page, anywhere after the form
 *     if ( $guard->check() ) { ... } // when the form is posted: true means spam
 *
 * Checks, in order:
 *  -  Always allow list: addresses on it skip every check.
 *  0. Repeat-bot block and your own Always block list (SE-A0, SE-H0).
 *  1. Honeypot: a hidden field people never see must stay empty (SE-B1).
 *  2. JavaScript token, set by the script (SE-C2).
 *  3. Timing: signed timestamp, not too fast, not expired (SE-D3, SE-E3, SE-G3).
 *  4. Interaction: a mouse, keyboard, touch or scroll event happened (SE-F4), and the visitor's
 *     own interaction token hasn't already been used for too many submissions (SE-R4).
 *  5. Content: your own words and patterns, throwaway email addresses (SE-K5, SE-M5).
 *
 * With a refresh_url (0.2.0), the interaction token is issued to each visitor by that endpoint
 * when they first touch the page, never printed in it: a bot that reads the page can't reuse it,
 * an address can only fetch act_per_hour of them, and each one passes token_uses submissions.
 * Without one, the page carries a rotating token that is the same for every visitor (as 0.1.0).
 */

namespace AccessNow\SpamEater;

final class Guard {

	const VERSION = '0.2.0';

	const HIDE_CSS = 'position:absolute!important;left:-9999px!important;top:-9999px!important;height:0!important;width:0!important;overflow:hidden!important;opacity:0!important;z-index:-1!important';

	const CODES = array(
		'ip_blocked'         => 'SE-A0',
		'ip_blocklist'       => 'SE-H0',
		'filled_honeypot'    => 'SE-B1',
		'missing_js_token'   => 'SE-C2',
		'tampered_timestamp' => 'SE-D3',
		'too_fast'           => 'SE-E3',
		'expired_token'      => 'SE-G3',
		'no_interaction'     => 'SE-F4',
		'reused_token'       => 'SE-R4',
		'blocked_words'      => 'SE-K5',
		'disposable_email'   => 'SE-M5',
	);

	const BLOCKLIST_MAX = 500;

	/** Most interaction-token ids remembered for counting uses. */
	const USED_MAX = 5000;

	/** @var array */
	private $config;

	/** @var Storage|null */
	private $storage;

	/** @var Content */
	private $content;

	/** @var Tokens */
	private $tokens;

	/** @var string */
	private $reason = '';

	/** @var int */
	private $field_count = 0;

	/** @var bool */
	private $script_printed = false;

	/**
	 * @param array $config {
	 *     @type string         $secret          Required. A long random string, kept private (32+ characters).
	 *     @type string|Storage $storage         A folder outside the web root, or a Storage. Without it,
	 *                                           addresses that keep filling in the honeypot aren't blocked.
	 *     @type int            $min_seconds     Forms sent sooner than this after loading are refused. Default 3.
	 *     @type int            $token_lifetime  Seconds a page's tokens stay valid (minimum 3600). Default two days.
	 *     @type string         $refresh_url     URL of a script that calls sendTokens(). Recommended: visitors get
	 *                                           their own interaction token from it (and cached pages fresh tokens).
	 *     @type int            $act_per_hour    Interaction tokens one address can fetch an hour (needs storage;
	 *                                           0 = no limit). Default 60.
	 *     @type int            $token_uses      Submissions one interaction token passes (needs storage; 0 = no
	 *                                           limit). Default 5: enough to fix a mistake and send again.
	 *     @type int            $block_after     Honeypot hits before an address is blocked (0 = never). Default 5.
	 *     @type int            $block_hours     How long a block lasts. Default 24.
	 *     @type string[]       $trusted_proxies Proxy addresses or CIDR ranges (Cloudflare, a load balancer).
	 *     @type string[]       $allow           Always allow: addresses or CIDR ranges that skip every check.
	 *     @type string[]       $block           Always block: addresses or CIDR ranges.
	 *     @type string|array   $words           Your own words, phrases or /regex/ patterns, one per line.
	 *     @type bool           $block_disposable Refuse throwaway email addresses. Default false.
	 *     @type callable       $on_block        function ( $reason, $code, $anonymised_ip ), for your own counts or log.
	 *     @type callable       $clock           function (): int, for tests. Default time().
	 * }
	 */
	public function __construct( array $config ) {
		$this->config = array_merge(
			array(
				'secret'           => '',
				'storage'          => null,
				'min_seconds'      => 3,
				'token_lifetime'   => 172800,
				'refresh_url'      => '',
				'act_per_hour'     => 60,
				'token_uses'       => 5,
				'block_after'      => 5,
				'block_hours'      => 24,
				'trusted_proxies'  => array(),
				'allow'            => array(),
				'block'            => array(),
				'words'            => '',
				'block_disposable' => false,
				'on_block'         => null,
				'clock'            => null,
			),
			$config
		);
		if ( strlen( (string) $this->config['secret'] ) < 32 ) {
			throw new \InvalidArgumentException( 'Spam Eater: "secret" must be a random string of at least 32 characters.' );
		}
		$storage = $this->config['storage'];
		if ( is_string( $storage ) && '' !== $storage ) {
			$storage = new FileStorage( $storage );
		}
		$this->storage = $storage instanceof Storage ? $storage : null;
		$this->tokens  = new Tokens( $this->config['secret'], $this->config['token_lifetime'], $this->config['clock'] );
		$this->content = new Content(
			$this->config['words'],
			$this->config['block_disposable'] ? dirname( __DIR__ ) . '/data/disposable-domains.txt' : null
		);
	}

	// =====================================================================
	// Output
	// =====================================================================

	/**
	 * The hidden fields, to print inside the <form>. Styles are inline, so they stay
	 * hidden wherever the markup ends up and no stylesheet is needed.
	 *
	 * @param string $group Optional array name to put the fields in, for form handlers that
	 *                      only read their own group (e.g. 'contact' gives contact[se_js]).
	 * @return string HTML.
	 */
	public function field( $group = '' ) {
		$name = function ( $key ) use ( $group ) {
			return '' === $group ? $key : $group . '[' . $key . ']';
		};
		$id = 'se-' . $this->fieldName() . '-' . ( ++$this->field_count );
		$t  = $this->tokens();

		return '<div class="se-wrap" aria-hidden="true" style="' . self::HIDE_CSS . '"'
			. ' data-js="' . $t['js'] . '"' . ( isset( $t['act'] ) ? ' data-act="' . $t['act'] . '"' : '' ) . ' data-issued="' . $t['issued'] . '"'
			. ( '' !== $this->config['refresh_url'] ? ' data-refresh="' . self::esc( $this->config['refresh_url'] ) . '"' : '' )
			. '>'
			. '<label for="' . $id . '">Leave this empty</label>'
			. '<input type="text" name="' . self::esc( $name( $this->fieldName() ) ) . '" id="' . $id . '" class="se-hp" value="" tabindex="-1" autocomplete="off"/>'
			. '<input type="hidden" name="' . self::esc( $name( 'se_js' ) ) . '" class="se-js" value=""/>'
			. '<input type="hidden" name="' . self::esc( $name( 'se_ts' ) ) . '" class="se-ts" value="' . $t['ts'] . '"/>'
			. '<input type="hidden" name="' . self::esc( $name( 'se_act' ) ) . '" class="se-act" value=""/>'
			. '</div>';
	}

	/**
	 * The small script that fills in the tokens, inline. Printed once per page; later
	 * calls return ''. To serve it as a file instead (for a strict Content Security
	 * Policy without nonces), use assets/spam-eater.js.
	 *
	 * @param string $nonce Optional CSP nonce for the <script> tag.
	 * @return string HTML.
	 */
	public function script( $nonce = '' ) {
		if ( $this->script_printed ) {
			return '';
		}
		$this->script_printed = true;
		$js = (string) file_get_contents( dirname( __DIR__ ) . '/assets/spam-eater.js' );
		return '<script' . ( '' !== $nonce ? ' nonce="' . self::esc( $nonce ) . '"' : '' ) . '>' . $js . '</script>';
	}

	/**
	 * Fresh tokens, for pages served from a cache. The interaction token is only included without
	 * a refresh_url; with one, sendTokens() gives each visitor their own.
	 *
	 * @return array{js:string,ts:string,issued:int,act?:string}
	 */
	public function tokens() {
		$t = array(
			'js'     => $this->tokens->token( 'js' ),
			'ts'     => $this->tokens->stamp(),
			'issued' => $this->now(),
		);
		if ( ! $this->issuesAct() ) {
			$t['act'] = $this->tokens->token( 'act' );
		}
		return $t;
	}

	/**
	 * The script at refresh_url. GET: fresh tokens, as JSON, for a cached page. POST (sent by the
	 * script when the visitor first touches the page, with the form's se_ts): the visitor's own
	 * interaction token for that timestamp, or a fresh timestamp too when theirs has expired.
	 *
	 * @param array|null $post   Default $_POST.
	 * @param array|null $server Default $_SERVER.
	 */
	public function sendTokens( $post = null, $server = null ) {
		$server = is_array( $server ) ? $server : $_SERVER;
		$body   = $this->tokens();
		if ( isset( $server['REQUEST_METHOD'] ) && 'POST' === $server['REQUEST_METHOD'] ) {
			$post = is_array( $post ) ? $post : $_POST; // phpcs:ignore
			$body = $this->issueAct( self::posted( $post, 'se_ts' ), Ip::client( $server, (array) $this->config['trusted_proxies'] ) );
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Cache-Control: no-store, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
			if ( null === $body ) {
				http_response_code( 429 );
			}
		}
		echo json_encode( null === $body ? array( 'error' => 'limit' ) : $body );
	}

	/**
	 * A visitor's interaction token (what sendTokens() answers a POST with).
	 *
	 * @param string $stamp The form's signed timestamp; a fresh one is issued when it's invalid or expired.
	 * @param string $ip    The visitor's address.
	 * @return array{ts:string,act:string}|null Null when the address has had its act_per_hour.
	 */
	public function issueAct( $stamp, $ip ) {
		if ( ! $this->allowIssue( $ip ) ) {
			return null;
		}
		$age = $this->tokens->verifyStamp( $stamp );
		if ( null === $age || $age > $this->tokens->lifetime() ) {
			$stamp = $this->tokens->stamp();
		}
		return array(
			'ts'  => $stamp,
			'act' => $this->tokens->actFor( $stamp ),
		);
	}

	// =====================================================================
	// Checking
	// =====================================================================

	/**
	 * Check a submission.
	 *
	 * @param array|null  $post    Submitted fields. Default $_POST. If you passed a group to
	 *                             field(), pass that group here: $_POST['contact'].
	 * @param string      $context 'full' (every check), 'basic' (honeypot, IP lists and
	 *                             content only, for requests that don't come from your form) or
	 *                             'login' (honeypot only, so nobody can be locked out).
	 * @param array|null  $server  Default $_SERVER.
	 * @return bool True when the submission is spam. See reason() and failCode().
	 */
	public function check( $post = null, $context = 'full', $server = null ) {
		$post         = is_array( $post ) ? $post : $_POST; // phpcs:ignore
		$server       = is_array( $server ) ? $server : $_SERVER;
		$this->reason = '';
		$ip           = Ip::client( $server, (array) $this->config['trusted_proxies'] );

		if ( '' !== $ip && Ip::matchesAny( $ip, (array) $this->config['allow'] ) ) {
			return false;
		}

		if ( 'login' !== $context ) {
			// Not reported through on_block, so a blocked bot can't cause a write storm.
			if ( $this->isBlocked( $ip ) ) {
				$this->reason = 'ip_blocked';
				return true;
			}
			if ( '' !== $ip && Ip::matchesAny( $ip, (array) $this->config['block'] ) ) {
				$this->reason = 'ip_blocklist';
				return true;
			}
		}

		$hp = isset( $post[ $this->fieldName() ] ) ? $post[ $this->fieldName() ] : '';
		if ( ! is_string( $hp ) || '' !== $hp ) {
			return $this->flag( 'filled_honeypot', $ip );
		}
		if ( 'login' === $context ) {
			return false;
		}

		if ( 'basic' !== $context ) {
			if ( ! $this->tokens->verify( 'js', self::posted( $post, 'se_js' ) ) ) {
				return $this->flag( 'missing_js_token', $ip );
			}
			$age = $this->tokens->verifyStamp( self::posted( $post, 'se_ts' ) );
			if ( null === $age ) {
				return $this->flag( 'tampered_timestamp', $ip );
			}
			if ( $age < (int) $this->config['min_seconds'] ) {
				return $this->flag( 'too_fast', $ip );
			}
			if ( $age > $this->tokens->lifetime() ) {
				return $this->flag( 'expired_token', $ip );
			}
			if ( $this->issuesAct() ) {
				$act = $this->tokens->verifyAct( self::posted( $post, 'se_ts' ), self::posted( $post, 'se_act' ) );
				if ( null === $act ) {
					return $this->flag( 'no_interaction', $ip );
				}
				if ( ! $this->useToken( $act ) ) {
					return $this->flag( 'reused_token', $ip );
				}
			} elseif ( ! $this->tokens->verify( 'act', self::posted( $post, 'se_act' ) ) ) {
				return $this->flag( 'no_interaction', $ip );
			}
		}

		if ( $this->content->isActive() ) {
			$found = $this->content->check( Content::collect( $post, array( 'se_js', 'se_ts', 'se_act', $this->fieldName() ) ) );
			if ( '' !== $found ) {
				return $this->flag( $found, $ip );
			}
		}
		return false;
	}

	/**
	 * Why the last check() refused the submission, e.g. 'too_fast'. '' when it passed.
	 *
	 * @return string
	 */
	public function reason() {
		return $this->reason;
	}

	/**
	 * A short reference code for the last refusal (e.g. SE-E3), safe to show visitors:
	 * it tells you why without telling a bot what to change. '' when it passed.
	 *
	 * @return string
	 */
	public function failCode() {
		return '' !== $this->reason ? self::CODES[ $this->reason ] : '';
	}

	/**
	 * The honeypot's field name: unique to the site, so bots can't learn it once for every site.
	 *
	 * @return string
	 */
	public function fieldName() {
		return 'se_' . substr( hash_hmac( 'sha256', 'field', $this->config['secret'] ), 0, 8 );
	}

	/**
	 * Whether an address is blocked for repeatedly filling in the honeypot.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public function isBlocked( $ip ) {
		if ( null === $this->storage || '' === $ip ) {
			return false;
		}
		$list  = $this->storage->read( 'blocked' );
		$entry = isset( $list[ $this->ipKey( $ip ) ] ) ? $list[ $this->ipKey( $ip ) ] : null;
		return ! empty( $entry['blocked_at'] ) && ( $this->now() - (int) $entry['blocked_at'] ) <= $this->blockSeconds();
	}

	/**
	 * Remove an address from the repeat-bot block list.
	 *
	 * @param string $ip IP address.
	 */
	public function unblock( $ip ) {
		if ( null === $this->storage ) {
			return;
		}
		$key = $this->ipKey( Ip::normalise( $ip ) );
		$this->storage->update(
			'blocked',
			function ( array $list ) use ( $key ) {
				unset( $list[ $key ] );
				return $list;
			}
		);
	}

	// =====================================================================
	// Internals
	// =====================================================================

	private function flag( $reason, $ip ) {
		$this->reason = $reason;
		if ( is_callable( $this->config['on_block'] ) ) {
			call_user_func( $this->config['on_block'], $reason, self::CODES[ $reason ], Ip::anonymise( $ip ) );
		}
		// Only a filled honeypot is a sure sign of a bot. The other checks can fail for real
		// people (an old browser, a tab left open too long), and counting those would block
		// someone who simply tried again.
		if ( 'filled_honeypot' === $reason ) {
			$this->countHit( $ip );
		}
		return true;
	}

	private function countHit( $ip ) {
		$threshold = (int) $this->config['block_after'];
		if ( null === $this->storage || '' === $ip || $threshold <= 0 ) {
			return;
		}
		$key    = $this->ipKey( $ip );
		$now    = $this->now();
		$window = $this->blockSeconds();
		$this->storage->update(
			'blocked',
			function ( array $list ) use ( $key, $now, $window, $threshold ) {
				foreach ( $list as $k => $e ) {
					$ref = ! empty( $e['blocked_at'] ) ? (int) $e['blocked_at'] : (int) ( isset( $e['last_seen'] ) ? $e['last_seen'] : 0 );
					if ( ( $now - $ref ) > $window ) {
						unset( $list[ $k ] );
					}
				}
				$entry = isset( $list[ $key ] ) ? $list[ $key ] : array( 'count' => 0, 'blocked_at' => 0 );
				unset( $list[ $key ] ); // Re-add at the end so the cap keeps the most recent entries.
				$entry['count']     = (int) $entry['count'] + 1;
				$entry['last_seen'] = $now;
				if ( $entry['count'] >= $threshold && empty( $entry['blocked_at'] ) ) {
					$entry['blocked_at'] = $now;
				}
				$list[ $key ] = $entry;
				return count( $list ) > Guard::BLOCKLIST_MAX ? array_slice( $list, -Guard::BLOCKLIST_MAX, null, true ) : $list;
			}
		);
	}

	/** Whether visitors get their own interaction tokens from refresh_url. */
	private function issuesAct() {
		return '' !== (string) $this->config['refresh_url'];
	}

	/**
	 * Count an interaction token issued to an address; false once it has had act_per_hour.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	private function allowIssue( $ip ) {
		$max = (int) $this->config['act_per_hour'];
		if ( null === $this->storage || '' === $ip || $max <= 0 ) {
			return true;
		}
		$key     = $this->ipKey( $ip );
		$now     = $this->now();
		$allowed = true;
		$this->storage->update(
			'issued',
			function ( array $list ) use ( $key, $now, $max, &$allowed ) {
				foreach ( $list as $k => $e ) {
					if ( $now - (int) $e['since'] >= 3600 ) {
						unset( $list[ $k ] );
					}
				}
				$entry = isset( $list[ $key ] ) ? $list[ $key ] : array( 'since' => $now, 'count' => 0 );
				if ( (int) $entry['count'] >= $max ) {
					$allowed = false;
					return $list;
				}
				$entry['count'] = (int) $entry['count'] + 1;
				$list[ $key ]   = $entry;
				return count( $list ) > Guard::BLOCKLIST_MAX ? array_slice( $list, -Guard::BLOCKLIST_MAX, null, true ) : $list;
			}
		);
		return $allowed;
	}

	/**
	 * Count a use of an interaction token; false once it has passed token_uses submissions. Counted
	 * before the content check, so a message refused for its words still uses one up.
	 *
	 * @param string $id The token's id.
	 * @return bool
	 */
	private function useToken( $id ) {
		$max = (int) $this->config['token_uses'];
		if ( null === $this->storage || $max <= 0 ) {
			return true;
		}
		$now      = $this->now();
		$lifetime = $this->tokens->lifetime();
		$allowed  = true;
		$this->storage->update(
			'used',
			function ( array $list ) use ( $id, $now, $lifetime, $max, &$allowed ) {
				foreach ( $list as $k => $e ) {
					if ( $now - (int) $e['at'] > $lifetime ) {
						unset( $list[ $k ] );
					}
				}
				$entry = isset( $list[ $id ] ) ? $list[ $id ] : array( 'at' => $now, 'count' => 0 );
				if ( (int) $entry['count'] >= $max ) {
					$allowed = false;
					return $list;
				}
				$entry['count'] = (int) $entry['count'] + 1;
				$list[ $id ]    = $entry;
				return count( $list ) > Guard::USED_MAX ? array_slice( $list, -Guard::USED_MAX, null, true ) : $list;
			}
		);
		return $allowed;
	}

	private function blockSeconds() {
		return max( 1, (int) $this->config['block_hours'] ) * 3600;
	}

	/** Keyed one-way hash of an address, so raw addresses are never stored. */
	private function ipKey( $ip ) {
		return substr( hash_hmac( 'sha256', 'spam-eater-ip|' . $ip, $this->config['secret'] ), 0, 32 );
	}

	private function now() {
		return $this->tokens->now();
	}

	private static function posted( array $post, $key ) {
		return ( isset( $post[ $key ] ) && is_string( $post[ $key ] ) ) ? trim( $post[ $key ] ) : '';
	}

	private static function esc( $value ) {
		return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' );
	}
}
