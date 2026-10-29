# Spam Eater for PHP forms

Stops form spam on any PHP site without a CAPTCHA. Visitors see no puzzles, there's no account to make, and nothing is sent to an outside service: every check runs on your own server.

It's the engine of [AccessNow Spam Eater](https://accessnow.com.au/projects/spam-eater/) for WordPress, packaged for plain PHP sites. It needs PHP 7.4 or later and has no dependencies. MIT licence.

## What it checks

| Check | Catches | Code |
|---|---|---|
| Honeypot: a hidden field people never see | bots that fill in every field | SE-B1 |
| JavaScript token, set by a small script | bots that don't run JavaScript | SE-C2 |
| Signed timestamp | forms sent within 3 seconds, tampered with, or left open for days | SE-E3, SE-D3, SE-G3 |
| Interaction: a mouse, keyboard, touch or scroll event | headless scripts that never touch the page | SE-F4 |
| Reused interaction token (with `refresh_url`) | bots that fetch one visitor's token and send many forms with it | SE-R4 |
| Repeat bots | addresses that fill in the honeypot 5 times are blocked for 24 hours | SE-A0 |
| Always allow / Always block | your own lists of addresses and CIDR ranges, IPv4 and IPv6 | SE-H0 |
| Your own words and patterns (optional) | spam typed by people: words, phrases or `/regex/` | SE-K5 |
| Throwaway email addresses (optional) | about 9,000 disposable email domains, bundled | SE-M5 |

Show the code to visitors when a form is refused. It tells you which check failed without telling a bot what to change.

## Install

With Composer:

```sh
composer require accessnow/spam-eater
```

Without Composer, download the ZIP, put the folder somewhere on your server, and `require 'spam-eater/autoload.php';`.

## Use

```php
use AccessNow\SpamEater\Guard;

$guard = new Guard( array(
    'secret'  => getenv( 'SPAM_EATER_SECRET' ),    // 32+ random characters, kept private
    'storage' => '/home/site/private/spam-eater', // a writable folder OUTSIDE the web root
) );
```

In the form, print the hidden fields. Print the script once, anywhere after the form:

```php
<form method="post">
    ...your fields...
    <?= $guard->field() ?>
    <button>Send</button>
</form>
<?= $guard->script() ?>
```

When the form is posted:

```php
if ( $guard->check() ) {
    http_response_code( 400 );
    exit( 'Sorry, your message could not be sent. Reference: ' . $guard->failCode() );
}
// Not spam: send the email.
```

Make a secret with `php -r "echo bin2hex(random_bytes(32));"`.

**Set a `refresh_url` too** (0.2.0): a script that calls `$guard->sendTokens()`, as in [`examples/tokens.php`](examples/tokens.php).
It must accept GET and POST from your own pages without a CSRF token. With it, each visitor gets their own
interaction token from that script when they first touch the page, and it's never in the page itself. Without
it, the page carries one token that's the same for every visitor, and a bot that reads the page once can copy
it into every form it sends: that is how a "Test" sign-up bot got past Spam Eater in October 2026.

A working contact form is in [`examples/`](examples). Run `php -S localhost:8765 -t examples` and open http://localhost:8765/contact.php.

## Options

| Option | Default | |
|---|---|---|
| `secret` | required | Signs the tokens and names the honeypot field, which is unique to your site. |
| `storage` | none | A folder outside the web root, or your own `Storage`. Without it, repeat bots aren't blocked. |
| `min_seconds` | `3` | Forms sent sooner than this after loading are refused. |
| `token_lifetime` | `172800` | How long a page's tokens last, in seconds (at least 3600). |
| `refresh_url` | none | A script that calls `$guard->sendTokens()`. Recommended: visitors get their own interaction token from it, and pages from a page cache fetch fresh tokens. |
| `act_per_hour` | `60` | Interaction tokens one address can fetch an hour (needs `storage`; `0` = no limit). |
| `token_uses` | `5` | Submissions one interaction token passes (needs `storage`; `0` = no limit): enough to fix a mistake and send again. |
| `block_after` | `5` | Honeypot hits before an address is blocked. `0` turns blocking off. |
| `block_hours` | `24` | How long a block lasts. |
| `trusted_proxies` | `[]` | Your proxy or CDN addresses (Cloudflare, a load balancer). **Set this behind a proxy**, or every visitor looks like the proxy. |
| `allow`, `block` | `[]` | Addresses or CIDR ranges to always allow or always block. |
| `words` | `''` | Your own words, phrases or `/regex/flags`, one per line. Matched as whole words, ignoring case. |
| `block_disposable` | `false` | Refuse throwaway email addresses. |
| `on_block` | none | `function ( $reason, $code, $anonymised_ip )`, for your own counts or log. |

## Other forms

- **Login forms:** use `$guard->check( null, 'login' )`. It checks only the honeypot, so password managers and visitors without JavaScript can still log in, and a blocked address can never lock out a real user.
- **Requests that don't come from your form** (a webhook, a payment callback): use `'basic'`. It checks the honeypot, the IP lists and the content, but not the tokens.
- **Forms that only read their own group of fields:** use `$guard->field( 'contact' )` and `$guard->check( $_POST['contact'] )`.
- **Forms added after the page loads** (pop-ups, AJAX): call `SpamEater.fill()` once the form is in the page.
- **A strict Content Security Policy:** pass a nonce, `$guard->script( $nonce )`, or serve `assets/spam-eater.js` as a file.
- **Storing the block list elsewhere:** implement `AccessNow\SpamEater\Storage`, which has two methods, `read()` and `update()`, and pass it as `storage`. It works with a database, Redis or APCu.

## Privacy

- No cookies, no tracking and no calls to outside services.
- What people type is checked in memory and never stored.
- The block list, and the counts behind `act_per_hour`, keep only a keyed one-way hash of each address, and their entries expire.
- `on_block` gets an anonymised address: the last octet of IPv4, or the last 80 bits of IPv6, set to zero.

## Tests

```sh
php tests/run.php
```

## Licence

MIT. The disposable email list comes from [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) (CC0).
