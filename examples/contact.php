<?php
/**
 * A plain PHP contact form protected by Spam Eater.
 * Run it with: php -S localhost:8765 -t examples   then open http://localhost:8765/contact.php
 */

$guard  = require __DIR__ . '/config.php';
$result = null;

if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
	if ( $guard->check() ) {
		http_response_code( 400 );
		$result = array( 'error', 'Sorry, your message could not be sent. Reference: ' . $guard->failCode() );
	} else {
		// Send the email or save the message here.
		$result = array( 'ok', 'Thanks, your message was sent.' );
	}
}

function e( $value ) {
	return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' );
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spam Eater demo</title>
<style>
	body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 2rem auto; padding: 0 1rem; color: #1d2327; background: #fff; }
	label { display: block; margin-top: 1rem; font-weight: 600; }
	input, textarea { width: 100%; box-sizing: border-box; padding: .5rem; font: inherit; }
	button { margin-top: 1rem; padding: .6rem 1.2rem; font: inherit; cursor: pointer; }
	.ok, .error { padding: .75rem 1rem; border-radius: 4px; }
	.ok { background: #e7f6ec; }
	.error { background: #fcecec; }
</style>
</head>
<body>
<h1>Contact us</h1>
<?php if ( $result ) : ?>
	<p class="<?php echo e( $result[0] ); ?>" role="status"><?php echo e( $result[1] ); ?></p>
<?php endif; ?>
<form method="post" action="contact.php">
	<label for="name">Name</label>
	<input id="name" name="name" required>
	<label for="email">Email</label>
	<input id="email" name="email" type="email" required>
	<label for="message">Message</label>
	<textarea id="message" name="message" rows="5" required></textarea>
	<?php echo $guard->field(); ?>
	<button type="submit">Send</button>
</form>
<?php echo $guard->script(); ?>
</body>
</html>
