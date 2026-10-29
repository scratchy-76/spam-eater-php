<?php
/**
 * Where Spam Eater keeps its state: the list of addresses that keep filling in the hidden
 * field ('blocked'), and with a refresh_url the interaction tokens issued per address
 * ('issued') and used ('used'). Implement this to keep them in a database, Redis or APCu.
 */

namespace AccessNow\SpamEater;

interface Storage {

	/**
	 * Read a stored list.
	 *
	 * @param string $name List name.
	 * @return array Empty when nothing is stored.
	 */
	public function read( $name );

	/**
	 * Change a stored list atomically: read it, pass it to $change, store what comes back.
	 *
	 * @param string   $name   List name.
	 * @param callable $change function ( array $data ): array.
	 */
	public function update( $name, callable $change );
}
