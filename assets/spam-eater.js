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
	var asking = null; // The request for the visitor's interaction token, while it's on its way.
	var lastAsk = 0;

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

	// With an endpoint, the interaction token isn't in the page: once the visitor has touched it,
	// ask for their own, for the form's timestamp (a fresh timestamp comes back if it has expired).
	function askAct() {
		var first = document.querySelector( '.se-wrap[data-refresh]' );
		if ( asking ) {
			return asking;
		}
		if ( ! acted || ! first || first.hasAttribute( 'data-act' ) || ! window.fetch || Date.now() - lastAsk < 10000 ) {
			return null;
		}
		var ts = first.querySelector( '.se-ts' );
		var body = new FormData();
		body.append( 'se_ts', ts ? ts.value : '' );
		lastAsk = Date.now();
		asking = window
			.fetch( first.getAttribute( 'data-refresh' ), { method: 'POST', body: body, credentials: 'same-origin', cache: 'no-store' } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( t ) {
				if ( ! t || ! t.act ) {
					return;
				}
				var all = wraps();
				for ( var i = 0; i < all.length; i++ ) {
					if ( ! all[ i ].hasAttribute( 'data-refresh' ) ) {
						continue;
					}
					all[ i ].setAttribute( 'data-act', t.act );
					var field = all[ i ].querySelector( '.se-ts' );
					if ( field ) {
						field.value = t.ts;
					}
				}
				fill();
			} )
			.catch( function () {} )
			.then( function () {
				asking = null;
			} );
		return asking;
	}

	// A form sent in the same moment as the first touch (a click or Enter straight after autofill)
	// would go before the visitor's token arrives: hold it until then (at most 4 seconds), and send
	// it again so the form's own handlers run as usual.
	function onSubmit( e ) {
		fill();
		var form = e.target;
		var wrap = form && form.querySelector ? form.querySelector( '.se-wrap[data-refresh]' ) : null;
		if ( ! wrap || wrap.hasAttribute( 'data-act' ) || ! acted || ! form.requestSubmit || form.seHeld ) {
			return;
		}
		var wait = askAct();
		if ( ! wait ) {
			return;
		}
		e.preventDefault();
		e.stopImmediatePropagation();
		var submitter = e.submitter && e.submitter.form === form ? e.submitter : undefined;
		Promise.race( [ wait, new Promise( function ( resolve ) {
			setTimeout( resolve, 4000 );
		} ) ] ).then( function () {
			fill();
			form.seHeld = true;
			try {
				form.requestSubmit( submitter );
			} finally {
				form.seHeld = false;
			}
		} );
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
					if ( t.act ) {
						all[ i ].setAttribute( 'data-act', t.act );
					} else {
						all[ i ].removeAttribute( 'data-act' ); // The visitor's own was for the old timestamp.
					}
					all[ i ].setAttribute( 'data-issued', t.issued );
					var ts = all[ i ].querySelector( '.se-ts' );
					if ( ts ) {
						ts.value = t.ts;
					}
				}
				fill();
				askAct();
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
			askAct();
		}
	}

	// For forms added after the page loads: call SpamEater.fill() once they are in the page.
	window.SpamEater = {
		fill: function () {
			fill();
			refresh();
			askAct();
		},
	};

	var passive = { passive: true };
	document.addEventListener( 'mousemove', onAct, passive );
	document.addEventListener( 'keydown', onAct );
	document.addEventListener( 'touchstart', onAct, passive );
	document.addEventListener( 'scroll', onAct, passive );
	document.addEventListener( 'focusin', window.SpamEater.fill );
	document.addEventListener( 'submit', onSubmit, true );

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', window.SpamEater.fill );
	} else {
		window.SpamEater.fill();
	}
} )();
