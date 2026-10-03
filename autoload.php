<?php
/**
 * For sites without Composer: require this file instead of vendor/autoload.php.
 */

spl_autoload_register(
	function ( $class ) {
		$prefix = 'AccessNow\\SpamEater\\';
		if ( 0 === strpos( $class, $prefix ) ) {
			$file = __DIR__ . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
			if ( is_file( $file ) ) {
				require $file;
			}
		}
	}
);
