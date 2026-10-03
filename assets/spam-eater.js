/*! Spam Eater (MIT) — fills in the hidden anti-spam fields. https://accessnow.com.au/projects/spam-eater/ */
( function () {
	'use strict';
	if ( window.SpamEater ) {
		return; // Already on the page.
	}

	var REFRESH_AFTER = 43200; // Seconds before a cached page's tokens are refreshed.
	var acted = false;
	var refreshing = false;
	var lastRefresh = 0;

	function wraps() {
		return document.querySelectorAll( '.se-wrap' );
	}

	function fill() {
		var all = wraps();
		for ( var i = 0; i < all.length; i++ ) {
			var wrap = all[ i ];
			var js = wrap.querySelector( '.se-js' );
			var act = wrap.querySelector( '.se-act' );
			if ( js ) {
				js.value = wrap.getAttribute( 'data-js' ) || '';
			}
			if ( act ) {
				act.value = acted ? wrap.getAttribute( 'data-act' ) || '' : '';
			}
		}
	}

	// A page from a page cache may hold old tokens: fetch fresh ones once, from your own site.
	function refresh() {
		var first = document.querySelector( '.se-wrap[data-refresh]' );
		if ( refreshing || ! first || ! window.fetch ) {
			return;
		}
		var issued = parseInt( first.getAttribute( 'data-issued' ), 10 ) || 0;
		if ( Date.now() / 1000 - issued < REFRESH_AFTER || Date.now() - lastRefresh < 60000 ) {
			return;
		}
		refreshing = true;
		lastRefresh = Date.now();
		window
			.fetch( first.getAttribute( 'data-refresh' ), { credentials: 'same-origin', cache: 'no-store' } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( t ) {
				if ( ! t || ! t.js ) {
					return;
				}
				var all = wraps();
				for ( var i = 0; i < all.length; i++ ) {
					all[ i ].setAttribute( 'data-js', t.js );
					all[ i ].setAttribute( 'data-act', t.act );
					all[ i ].setAttribute( 'data-issued', t.issued );
					var ts = all[ i ].querySelector( '.se-ts' );
					if ( ts ) {
						ts.value = t.ts;
					}
				}
				fill();
			} )
			.catch( function () {} )
			.then( function () {
				refreshing = false;
			} );
	}

	function onAct() {
		if ( ! acted ) {
			acted = true;
			fill();
		}
	}

	// For forms added after the page loads: call SpamEater.fill() once they are in the page.
	window.SpamEater = {
		fill: function () {
			fill();
			refresh();
		},
	};

	var passive = { passive: true };
	document.addEventListener( 'mousemove', onAct, passive );
	document.addEventListener( 'keydown', onAct );
	document.addEventListener( 'touchstart', onAct, passive );
	document.addEventListener( 'scroll', onAct, passive );
	document.addEventListener( 'focusin', window.SpamEater.fill );
	document.addEventListener( 'submit', fill, true );

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', window.SpamEater.fill );
	} else {
		window.SpamEater.fill();
	}
} )();
