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

	/** @var string|callable|null Where the throwaway email domains come from, or null when that check is off. */
	private $disposable_source;

	/** @var array<string,bool>|null */
	private $disposable;

	/**
	 * @param string|string[] $words           One rule per line (or per array item). A line written
	 *                                         as /pattern/flags is a regular expression; any other
	 *                                         line is a word or phrase, matched as whole words.
	 * @param string|callable|null $disposable Throwaway email domains: a file with one domain per line,
	 *                                         or a function returning array( domain => true ). Null skips
	 *                                         that check. Loaded only when a submission holds an email address.
	 */
	public function __construct( $words = '', $disposable = null ) {
		$this->rules             = self::compile( is_array( $words ) ? implode( "\n", $words ) : (string) $words );
		$this->disposable_source = $disposable;
	}

	/**
	 * Whether there is anything to check, so callers can skip collecting the text.
	 *
	 * @return bool
	 */
	public function isActive() {
		return ! empty( $this->rules ) || null !== $this->disposable_source;
	}

	/**
	 * Check submitted text.
	 *
	 * @param string[] $values Submitted text (see collect()).
	 * @return string '' when it passes, 'blocked_words' or 'disposable_email'.
	 */
	public function check( array $values ) {
		if ( $this->matchesRules( $values ) ) {
			return 'blocked_words';
		}
		if ( null !== $this->disposable_source && $this->hasDisposableEmail( $values ) ) {
			return 'disposable_email';
		}
		return '';
	}

	/**
	 * Whether any words or patterns are set.
	 *
	 * @return bool
	 */
	public function hasRules() {
		return ! empty( $this->rules );
	}

	/**
	 * Whether any value matches any word or pattern. A pattern that fails at run time
	 * (for example by hitting PCRE's backtracking limit) counts as no match.
	 *
	 * @param string[] $values Submitted text.
	 * @return bool
	 */
	public function matchesRules( array $values ) {
		foreach ( $this->rules as $rule ) {
			foreach ( $values as $value ) {
				if ( 1 === @preg_match( $rule, $value ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Collect the string values of submitted data, skipping passwords, tokens, card
	 * details and Spam Eater's own fields.
	 *
	 * @param array         $data  Submitted data.
	 * @param string[]      $skip  Field names to leave out.
	 * @param callable|null $clean function ( string ): string to clean each value. Default: drop invalid UTF-8.
	 * @return string[]
	 */
	public static function collect( array $data, array $skip = array(), $clean = null ) {
		$values = array();
		self::walk( $data, $skip, $values, 0, is_callable( $clean ) ? $clean : array( __CLASS__, 'cleanUtf8' ) );
		return $values;
	}

	/**
	 * Drop invalid UTF-8, so /u patterns can run.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	public static function cleanUtf8( $value ) {
		if ( preg_match( '//u', $value ) ) {
			return $value;
		}
		if ( ! function_exists( 'mb_convert_encoding' ) ) {
			return '';
		}
		$substitute = mb_substitute_character();
		mb_substitute_character( 'none' );
		$value = (string) mb_convert_encoding( $value, 'UTF-8', 'UTF-8' );
		mb_substitute_character( $substitute );
		return $value;
	}

	private static function walk( array $data, array $skip, array &$values, $depth, callable $clean ) {
		if ( $depth > 5 ) {
			return;
		}
		foreach ( $data as $key => $value ) {
			if ( count( $values ) >= self::MAX_VALUES ) {
				return;
			}
			$key = (string) $key;
			if ( in_array( $key, $skip, true ) || preg_match( '/pass|pwd|nonce|token|card|cvc|cvv|captcha|csrf|_wp_http_referer|security/i', $key ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				self::walk( $value, $skip, $values, $depth + 1, $clean );
			} elseif ( is_string( $value ) && '' !== trim( $value ) ) {
				$values[] = $clean( substr( $value, 0, self::MAX_LENGTH ) );
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

	/**
	 * Whether a rule line is a regular expression: /pattern/ with optional i, m, s, u or x flags.
	 *
	 * @param string $line Rule line.
	 * @return bool
	 */
	public static function isRegex( $line ) {
		return strlen( $line ) > 2 && '/' === $line[0] && (bool) preg_match( '#^/.+/[imsux]*$#s', $line );
	}

	/**
	 * Whether a regular expression compiles, without letting PHP print a warning.
	 *
	 * @param string $pattern Pattern with delimiters.
	 * @return bool
	 */
	public static function compiles( $pattern ) {
		$failed = false;
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Catches the compile warning of a pattern someone typed, for this one call only, to tell them it is invalid.
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

	/**
	 * Whether any value holds an email address at a throwaway domain (or a subdomain of one).
	 *
	 * @param string[] $values Submitted text.
	 * @return bool
	 */
	public function hasDisposableEmail( array $values ) {
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
	 * Read a list of domains, one per line; blank lines and # comments are ignored.
	 *
	 * @param string $file Path.
	 * @return array<string,bool> Domain => true.
	 */
	public static function loadDomains( $file ) {
		$domains = array();
		$lines   = ( '' !== $file && is_readable( $file ) ) ? file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) : false;
		foreach ( (array) $lines as $line ) {
			$line = trim( $line );
			if ( '' !== $line && '#' !== $line[0] ) {
				$domains[ strtolower( $line ) ] = true;
			}
		}
		return $domains;
	}

	/**
	 * How many throwaway email domains are on the list.
	 *
	 * @return int
	 */
	public function countDomains() {
		$this->isDisposableDomain( 'example.invalid' ); // Loads the list.
		return count( $this->disposable );
	}

	/**
	 * Whether a domain, or a domain it belongs to, is a throwaway email service.
	 *
	 * @param string $domain Domain part of an email address.
	 * @return bool
	 */
	public function isDisposableDomain( $domain ) {
		if ( null === $this->disposable ) {
			$this->disposable = is_callable( $this->disposable_source )
				? (array) call_user_func( $this->disposable_source )
				: self::loadDomains( (string) $this->disposable_source );
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
