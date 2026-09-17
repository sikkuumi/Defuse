<?php
// EXPECT-NONE
//
// 2,547 FINDINGS ON CODE THAT WAS ESCAPING CORRECTLY.
//
// A scan of WordPress (2,119 files) produced 3,558 findings, and 2,971 of them
// were XSS. 2,547 of those were shapes from this file: `echo esc_html( $x )`.
//
// WordPress does not use `htmlspecialchars` directly. It has its own escaping
// API - esc_html, esc_attr, esc_url, esc_js, wp_kses - which is the single most
// consistently applied escaping convention in any large PHP codebase, and the
// scanner knew none of it. So every correctly escaped line in the largest PHP
// project in the world was reported as cross-site scripting.
//
// AND 223 OF THEM WERE FLOW-VERIFIED. That is the worse half. The tracer found
// a real source, followed it correctly, and stopped at
//
//     esc_html( $result->get_error_message() )
//
// calling it proven. A signature-based guess that lands on escaped code is
// noise; a PROOF that lands on escaped code is a false statement, because the
// sanitiser it walked through was in the argument list it was reading.
//
// Fifth time this project has punished a fix, and by far the largest.

function wp_shapes( $user, $url, $version_text, $app_name, $id, $screen_id ) {
	// The four workhorses. In WordPress source these appear tens of thousands
	// of times and are the correct, documented way to output anything.
	echo esc_html( $user->user_login );
	echo esc_url( $url );
	echo esc_attr( $version_text );
	echo esc_js( $screen_id );

	// Escaped inside an assembled string - the shape that made this hard,
	// because the escaper is one level down inside a concatenation.
	echo '<img class="pinkynail" src="' . esc_url( $url ) . '" alt="" />';
	echo '<strong>' . esc_html( $app_name ) . '</strong>';

	// The translate-and-escape family. Two jobs in one call, and the escaping
	// half is what matters here.
	echo esc_html__( 'Settings saved.', 'default' );
	echo esc_attr_x( 'Search', 'placeholder', 'default' );

	// wp_kses is a FILTERING escaper: it permits a fixed set of tags and strips
	// everything else. Allowing <em> on purpose is not the same as allowing
	// <script> by accident, and it is the intended safe form for rich text.
	echo wp_kses_post( $app_name );

	// Numbers and JSON. absint cannot return markup; wp_json_encode with the
	// HEX flags cannot emit a bare `<`.
	echo absint( $id );
	echo wp_json_encode( $app_name, JSON_HEX_TAG | JSON_HEX_AMP );

	// printf with every value escaped - same proof, different mechanism.
	printf( '<a href="%1$s">%2$s</a>', esc_url( $url ), esc_html( $app_name ) );
}

// STILL REPORTED, and deliberately not in this file: `echo $_GET['name']`, and
// the half-escaped form `'<a href="' . esc_url($u) . '">' . $label . '</a>'`
// where one value is raw. See vulnerable/xss.php - if the proof added here also
// silences those, this fixture passing means nothing.
