<?php
/**
 * Content checks: the site's own words and patterns, and throwaway email addresses.
 * Everything happens in memory; submitted text is never stored.
 */

namespace AccessNow\SpamEater;

final class Content {

	const MAX_VALUES  = 300;
	const MAX_LENGTH  = 20000;
	const MAX_PATTERN = 300;

	/** @var string[] Compiled regular expressions. */
	private $rules;

	/** @var string|null Path to the list of throwaway email domains, or null when that check is off. */
	private $disposable_file;

	/** @var array<string,bool>|null */
	private $disposable;

	/**
	 * @param string|string[] $words           One rule per line (or per array item). A line written
	 *                                         as /pattern/flags is a regular expression; any other
	 *                                         line is a word or phrase, matched as whole words.
	 * @param string|null     $disposable_file List of throwaway email domains, or null to skip that check.
	 */
	public function __construct( $words = '', $disposable_file = null ) {
		$this->rules           = self::compile( is_array( $words ) ? implode( "\n", $words ) : (string) $words );
		$this->disposable_file = $disposable_file;
	}

	/**
	 * Whether there is anything to check, so callers can skip collecting the text.
	 *
	 * @return bool
	 */
	public function isActive() {
		return ! empty( $this->rules ) || null !== $this->disposable_file;
	}

	/**
	 * Check submitted text.
	 *
	 * @param string[] $values Submitted text (see collect()).
	 * @return string '' when it passes, 'blocked_words' or 'disposable_email'.
	 */
	public function check( array $values ) {
		foreach ( $this->rules as $rule ) {
			foreach ( $values as $value ) {
				if ( 1 === @preg_match( $rule, $value ) ) {
					return 'blocked_words';
				}
			}
		}
		if ( null !== $this->disposable_file && $this->hasDisposableEmail( $values ) ) {
			return 'disposable_email';
		}
		return '';
	}

	/**
	 * Collect the string values of submitted data, skipping passwords, tokens, card
	 * details and Spam Eater's own fields.
	 *
	 * @param array    $data Submitted data.
	 * @param string[] $skip Field names to leave out.
	 * @return string[]
	 */
	public static function collect( array $data, array $skip = array() ) {
		$values = array();
		self::walk( $data, $skip, $values, 0 );
		return $values;
	}

	private static function walk( array $data, array $skip, array &$values, $depth ) {
		if ( $depth > 5 ) {
			return;
		}
		foreach ( $data as $key => $value ) {
			if ( count( $values ) >= self::MAX_VALUES ) {
				return;
			}
			$key = (string) $key;
			if ( in_array( $key, $skip, true ) || preg_match( '/pass|pwd|nonce|token|card|cvc|cvv|captcha|csrf|security/i', $key ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				self::walk( $value, $skip, $values, $depth + 1 );
			} elseif ( is_string( $value ) && '' !== trim( $value ) ) {
				$value = substr( $value, 0, self::MAX_LENGTH );
				if ( function_exists( 'mb_convert_encoding' ) && ! preg_match( '//u', $value ) ) {
					$value = mb_convert_encoding( $value, 'UTF-8', 'UTF-8' ); // Drop invalid UTF-8 so /u patterns can run.
				}
				$values[] = $value;
			}
		}
	}

	/**
	 * Turn rule lines into regular expressions. Invalid or over-long patterns are skipped.
	 *
	 * @param string $text One rule per line; blank lines and # comments are ignored.
	 * @return string[]
	 */
	public static function compile( $text ) {
		$rules = array();
		$words = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			if ( '/' === $line[0] && strlen( $line ) > 1 ) {
				if ( strlen( $line ) <= self::MAX_PATTERN && self::isRegex( $line ) && self::compiles( $line ) ) {
					$rules[] = $line;
				}
				continue;
			}
			$quoted  = preg_replace( '/\s+/', '\\s+', preg_quote( $line, '/' ) );
			$before  = preg_match( '/^[\p{L}\p{N}]/u', $line ) ? '(?<![\p{L}\p{N}])' : '';
			$after   = preg_match( '/[\p{L}\p{N}]$/u', $line ) ? '(?![\p{L}\p{N}])' : '';
			$words[] = $before . $quoted . $after;
		}
		// Words go into one expression of up to 50 alternatives at a time.
		foreach ( array_chunk( $words, 50 ) as $chunk ) {
			array_unshift( $rules, '/' . implode( '|', $chunk ) . '/iu' );
		}
		return $rules;
	}

	private static function isRegex( $line ) {
		return strlen( $line ) > 2 && '/' === $line[0] && (bool) preg_match( '#^/.+/[imsux]*$#s', $line );
	}

	private static function compiles( $pattern ) {
		$failed = false;
		set_error_handler(
			function () use ( &$failed ) {
				$failed = true;
				return true;
			}
		);
		$result = preg_match( $pattern, '' );
		restore_error_handler();
		return ! $failed && false !== $result;
	}

	private function hasDisposableEmail( array $values ) {
		foreach ( $values as $value ) {
			if ( false === strpos( $value, '@' ) || ! preg_match_all( '/[^\s@<>"\',;:()\[\]]+@([a-z0-9.-]+\.[a-z]{2,})/i', $value, $m ) ) {
				continue;
			}
			foreach ( $m[1] as $domain ) {
				if ( $this->isDisposableDomain( $domain ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Whether a domain, or a domain it belongs to, is a throwaway email service.
	 *
	 * @param string $domain Domain part of an email address.
	 * @return bool
	 */
	public function isDisposableDomain( $domain ) {
		if ( null === $this->disposable ) {
			$this->disposable = array();
			$lines            = ( null !== $this->disposable_file && is_readable( $this->disposable_file ) )
				? file( $this->disposable_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES )
				: false;
			foreach ( (array) $lines as $line ) {
				$line = trim( $line );
				if ( '' !== $line && '#' !== $line[0] ) {
					$this->disposable[ strtolower( $line ) ] = true;
				}
			}
		}
		$parts = explode( '.', strtolower( trim( $domain, '. ' ) ) );
		while ( count( $parts ) >= 2 ) {
			if ( isset( $this->disposable[ implode( '.', $parts ) ] ) ) {
				return true;
			}
			array_shift( $parts );
		}
		return false;
	}
}
