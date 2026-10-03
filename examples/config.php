<?php
/**
 * Shared setup for the demo. In your own site, keep the secret out of the code
 * (an environment variable or a config file outside the web root) and put the
 * storage folder outside the web root too.
 */

use AccessNow\SpamEater\Guard;

require dirname( __DIR__ ) . '/autoload.php';

$local = __DIR__ . '/config.local.php';
if ( ! is_file( $local ) ) {
	// First run: make a secret for this copy of the demo.
	file_put_contents( $local, "<?php\nreturn " . var_export( array( 'secret' => bin2hex( random_bytes( 32 ) ) ), true ) . ";\n" );
}
$settings = require $local;

return new Guard(
	array(
		'secret'           => $settings['secret'],
		'storage'          => sys_get_temp_dir() . '/spam-eater-demo', // Never inside the web root.
		'refresh_url'      => 'tokens.php',
		'words'            => "viagra\n/https?:\\/\\/\\S+\\.ru\\b/i",
		'block_disposable' => true,
	)
);
