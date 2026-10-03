<?php
/**
 * IP address helpers: finding the visitor's address, and matching addresses and CIDR ranges.
 */

namespace AccessNow\SpamEater;

final class Ip {

	/**
	 * The visitor's address. REMOTE_ADDR is used unless the request comes from a trusted
	 * proxy; only then is X-Forwarded-For read, right to left, skipping trusted proxies.
	 * The header is never trusted by default.
	 *
	 * @param array    $server  $_SERVER or an equivalent.
	 * @param string[] $proxies Trusted proxy addresses or CIDR ranges.
	 * @return string Normalised IP, or '' when unknown.
	 */
	public static function client( array $server, array $proxies = array() ) {
		$remote = isset( $server['REMOTE_ADDR'] ) ? self::normalise( (string) $server['REMOTE_ADDR'] ) : '';
		$ip     = $remote;

		if ( '' !== $remote && ! empty( $proxies ) && self::matchesAny( $remote, $proxies ) && ! empty( $server['HTTP_X_FORWARDED_FOR'] ) ) {
			foreach ( array_reverse( explode( ',', (string) $server['HTTP_X_FORWARDED_FOR'] ) ) as $hop ) {
				$hop = self::normalise( $hop );
				if ( '' === $hop ) {
					break; // Malformed entry: stop at the last address we could verify.
				}
				$ip = $hop;
				if ( ! self::matchesAny( $hop, $proxies ) ) {
					break; // First untrusted hop is the client.
				}
			}
		}
		return $ip;
	}

	/**
	 * Validate and normalise an IP address. Strips ports and IPv6 brackets.
	 *
	 * @param string $ip Raw value.
	 * @return string Normalised IP, or '' when invalid.
	 */
	public static function normalise( $ip ) {
		$ip = trim( (string) $ip );
		if ( preg_match( '/^\[([^\]]+)\](?::\d+)?$/', $ip, $m ) ) {
			$ip = $m[1];
		} elseif ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $ip, $m ) ) {
			$ip = $m[1];
		}
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$packed = inet_pton( $ip );
		return false === $packed ? '' : (string) inet_ntop( $packed );
	}

	/**
	 * Whether an IP matches any address or CIDR range in the list.
	 *
	 * @param string   $ip     Normalised IP.
	 * @param string[] $ranges IPs or CIDR ranges.
	 * @return bool
	 */
	public static function matchesAny( $ip, array $ranges ) {
		foreach ( $ranges as $range ) {
			if ( self::inRange( $ip, (string) $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether an IP is equal to an address or inside a CIDR range (IPv4 or IPv6).
	 *
	 * @param string $ip    Normalised IP.
	 * @param string $range IP or CIDR range.
	 * @return bool
	 */
	public static function inRange( $ip, $range ) {
		$bits = null;
		if ( false !== strpos( $range, '/' ) ) {
			list( $range, $bits ) = explode( '/', $range, 2 );
			if ( ! ctype_digit( $bits ) ) {
				return false;
			}
			$bits = (int) $bits;
		}
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) || false === filter_var( $range, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$ip_bin    = inet_pton( $ip );
		$range_bin = inet_pton( $range );
		if ( false === $ip_bin || false === $range_bin || strlen( $ip_bin ) !== strlen( $range_bin ) ) {
			return false;
		}
		if ( null === $bits ) {
			return $ip_bin === $range_bin;
		}
		if ( $bits < 0 || $bits > strlen( $ip_bin ) * 8 ) {
			return false;
		}
		$bytes = intdiv( $bits, 8 );
		if ( substr( $ip_bin, 0, $bytes ) !== substr( $range_bin, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $range_bin[ $bytes ] ) & $mask );
	}

	/**
	 * Anonymise an address for display: the last octet of IPv4, the last 80 bits of IPv6.
	 *
	 * @param string $ip Normalised IP.
	 * @return string
	 */
	public static function anonymise( $ip ) {
		$packed = @inet_pton( $ip );
		if ( false === $packed ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			return (string) inet_ntop( substr( $packed, 0, 3 ) . "\0" );
		}
		return (string) inet_ntop( substr( $packed, 0, 6 ) . str_repeat( "\0", 10 ) );
	}
}
