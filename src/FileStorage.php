<?php
/**
 * Keeps lists as JSON files in a folder, with a file lock around every change.
 * Put the folder outside the web root, or the block list can be downloaded.
 */

namespace AccessNow\SpamEater;

final class FileStorage implements Storage {

	/** @var string */
	private $dir;

	/**
	 * @param string $dir A writable folder outside the web root. Created if missing.
	 */
	public function __construct( $dir ) {
		$this->dir = rtrim( (string) $dir, '/\\' );
		if ( ! is_dir( $this->dir ) && ! @mkdir( $this->dir, 0700, true ) && ! is_dir( $this->dir ) ) {
			throw new \RuntimeException( 'Spam Eater: cannot create the storage folder ' . $this->dir );
		}
	}

	public function read( $name ) {
		$file = $this->path( $name );
		if ( ! is_readable( $file ) ) {
			return array();
		}
		$handle = fopen( $file, 'rb' );
		if ( false === $handle ) {
			return array();
		}
		flock( $handle, LOCK_SH );
		$json = stream_get_contents( $handle );
		flock( $handle, LOCK_UN );
		fclose( $handle );
		$data = json_decode( (string) $json, true );
		return is_array( $data ) ? $data : array();
	}

	public function update( $name, callable $change ) {
		$handle = fopen( $this->path( $name ), 'c+b' );
		if ( false === $handle ) {
			return; // Can't write: fail open, a form must never break because of the block list.
		}
		flock( $handle, LOCK_EX );
		$data = json_decode( (string) stream_get_contents( $handle ), true );
		$data = $change( is_array( $data ) ? $data : array() );
		ftruncate( $handle, 0 );
		rewind( $handle );
		fwrite( $handle, (string) json_encode( $data ) );
		fflush( $handle );
		flock( $handle, LOCK_UN );
		fclose( $handle );
	}

	private function path( $name ) {
		return $this->dir . '/' . preg_replace( '/[^a-z0-9_-]/i', '', (string) $name ) . '.json';
	}
}
