<?php
/**
 * Signed tokens: the rotating JavaScript and interaction tokens, and the signed
 * timestamp that dates a form. All HMAC-SHA256 with the site's secret.
 */

namespace AccessNow\SpamEater;

final class Tokens {

	/** @var string */
	private $secret;

	/** @var int */
	private $lifetime;

	/** @var callable|null */
	private $clock;

	/**
	 * @param string        $secret   Site secret.
	 * @param int           $lifetime Seconds a token stays valid (minimum one hour). Tokens rotate
	 *                                every half lifetime, and the previous one is still accepted.
	 * @param callable|null $clock    function (): int, for tests. Default time().
	 */
	public function __construct( $secret, $lifetime = 172800, $clock = null ) {
		$this->secret   = (string) $secret;
		$this->lifetime = max( 3600, (int) $lifetime );
		$this->clock    = $clock;
	}

	/**
	 * @return int Seconds a token stays valid.
	 */
	public function lifetime() {
		return $this->lifetime;
	}

	/**
	 * @return int Current time, from the clock.
	 */
	public function now() {
		return is_callable( $this->clock ) ? (int) call_user_func( $this->clock ) : time();
	}

	/**
	 * HMAC-sign a value.
	 *
	 * @param string $data Data to sign.
	 * @return string 32 hex characters.
	 */
	public function sign( $data ) {
		return substr( hash_hmac( 'sha256', 'spam-eater|' . $data, $this->secret ), 0, 32 );
	}

	/**
	 * Rotation counter, like WordPress nonce ticks.
	 *
	 * @param int $offset How many ticks back.
	 * @return int
	 */
	public function tick( $offset = 0 ) {
		return (int) ceil( $this->now() / (int) floor( $this->lifetime / 2 ) ) - $offset;
	}

	/**
	 * The current token for a purpose ('js' or 'act').
	 *
	 * @param string $purpose Purpose.
	 * @return string
	 */
	public function token( $purpose ) {
		return $this->sign( $purpose . '|' . $this->tick() );
	}

	/**
	 * Check a rotating token. Accepts the current and previous tick, so a token is
	 * valid for between half and the whole lifetime.
	 *
	 * @param string $purpose 'js' or 'act'.
	 * @param mixed  $value   Submitted token.
	 * @return bool
	 */
	public function verify( $purpose, $value ) {
		if ( ! is_string( $value ) || '' === $value ) {
			return false;
		}
		for ( $i = 0; $i <= 1; $i++ ) {
			if ( hash_equals( $this->sign( $purpose . '|' . $this->tick( $i ) ), $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A signed timestamp, "time:signature".
	 *
	 * @return string
	 */
	public function stamp() {
		$time = $this->now();
		return $time . ':' . $this->sign( 'ts|' . $time );
	}

	/**
	 * Split a signed timestamp into its time and signature.
	 *
	 * @param mixed $signed "time:signature".
	 * @return array{0:string,1:string}|null Null when it isn't in that shape.
	 */
	public static function splitStamp( $signed ) {
		$parts = explode( ':', (string) $signed, 2 );
		if ( count( $parts ) !== 2 || '' === $parts[1] || ! ctype_digit( $parts[0] ) ) {
			return null;
		}
		return $parts;
	}

	/**
	 * Check a signed timestamp.
	 *
	 * @param mixed $signed "time:signature".
	 * @return int|null The stamp's age in seconds, or null when it is invalid.
	 */
	public function verifyStamp( $signed ) {
		$parts = self::splitStamp( $signed );
		if ( null === $parts || ! hash_equals( $this->sign( 'ts|' . $parts[0] ), $parts[1] ) ) {
			return null;
		}
		return $this->now() - (int) $parts[0];
	}
}
