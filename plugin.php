<?php
/*
Plugin Name: Domain Limiter RegEx
Plugin URI: https://github.com/089/domain-limiter-regex-yourls-plugin
Description: Only allow URLs from admin-specified domains, with an admin panel. Based on the Domain Limiter plugin by nicwaller and quantumweb.co.
Version: 1.2.0
Author: github.com/089
Author URI: https://github.com/089
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

yourls_add_filter( 'shunt_add_new_link', 'domainlimitregex_link_filter' );

function domainlimitregex_link_filter( $original_return, $url, $keyword = '', $title = '' ) {
	if ( domainlimitregex_environment_check() != true ) {
		$err = array();
		$err['status'] = 'fail';
		$err['code'] = 'error:configuration';
		$err['message'] = 'Problem with domain limit configuration. Check PHP error log.';
		$err['errorCode'] = '500';
		return $err;
	}

	// If the user is exempt, don't even bother checking.
	global $domainlimitregex_exempt_users;
	if ( in_array( YOURLS_USER, $domainlimitregex_exempt_users ) ) {
		return $original_return;
	}

    $domainlimitregex_list = json_decode(yourls_get_option('domainlimitregex_list'), TRUE);

	// global $domainlimitregex_list;
	$domain_whitelist = $domainlimitregex_list;

	// The plugin hook gives us the raw URL input by the user, but
	// it needs some cleanup before it's suitable for parse_url().
	$url = yourls_encodeURI( $url );
	$url = yourls_escape( yourls_sanitize_url( $url) );
	if ( !$url || $url == 'http://' || $url == 'https://' ) {
		$return['status']    = 'fail';
		$return['code']      = 'error:nourl';
		$return['message']   = yourls__( 'Missing or malformed URL' );
		$return['errorCode'] = '400';
		return yourls_apply_filter( 'add_new_link_fail_nourl', $return, $url, $keyword, $title );
	}

	$allowed = false;
	$requested_domain = parse_url($url, PHP_URL_HOST);
	foreach ( $domain_whitelist as $domain_permitted ) {
		if ( domainlimitregex_is_subdomain( $requested_domain, $domain_permitted ) ) {
			$allowed = true;
			break;
		}
		if ( domainlimitregex_matches_domain_pattern( $requested_domain, $domain_permitted ) ) {
			$allowed = true;
			break;
		}
	}

	if ( $allowed == true ) {
		return $original_return;
	}

	$return = array();
	$return['status'] = 'fail';
	$return['code'] = 'error:disallowedhost';
	$return['message'] = 'URL must be in ' . implode(', ', $domain_whitelist);
	$return['errorCode'] = '400';
	return $return;
}

/*
 * Determine whether test_domain is controlled by $parent_domain
 */
function domainlimitregex_is_subdomain( $test_domain, $parent_domain ) {
	if ( $test_domain == $parent_domain ) {
		return true;
	}

	// note that "notunbc.ca" is NOT a subdomain of "unbc.ca"
	// We CANNOT just compare the rightmost characters
	// unless we add a period in there first
	if ( substr( $parent_domain, 1, 1) != '.' ) {
		$parent_domain = '.' . $parent_domain;
	}

	$chklen = strlen($parent_domain);
	return ( $parent_domain == substr( $test_domain, 0-$chklen ) );
}

/*
 * Determine whether $test_domain matches given $domain_pattern
 */
function domainlimitregex_matches_domain_pattern( $test_domain, $domain_pattern ) {
	if ( $test_domain == $parent_domain ) {
		return true;
	}

	return preg_match( $domain_pattern, $test_domain );
}

// returns true if everything is configured right
function domainlimitregex_environment_check() {
        if (yourls_get_option('domainlimitregex_list') !== false) {
            $domainlimitregex_list = json_decode(yourls_get_option('domainlimitregex_list'), TRUE);
        } else {
            yourls_add_option('domainlimitregex_list');
        }

	if ( !isset( $domainlimitregex_list ) ) {
		error_log('Missing definition of $domainlimitregex_list in database');
		return false;
	} else if ( isset( $domainlimitregex_list ) && !is_array( $domainlimitregex_list ) ) {
		// be friendly and allow non-array definitions
		$domain = $domainlimitregex_list;
		$domainlimitregex_list = array( $domain );
		return true;
	}
	return true;
}


// Register your plugin admin page
yourls_add_action( 'plugins_loaded', 'domainlimitregex_init' );
function domainlimitregex_init() {
    yourls_register_plugin_page( 'domainlimitregex', 'Domain Limiter RexEx Settings', 'domainlimitregex_display_page' );
}

// The function that will draw the admin page
function domainlimitregex_display_page() {
    // Check if a form was submitted
    if( isset( $_POST['domainlimitregex_list'] ) )
            domainlimitregex_config_update_option();

	global $domainlimitregex_exempt_users;
    $domainlimitregex_list_option = yourls_get_option( 'domainlimitregex_list' );
    foreach (json_decode($domainlimitregex_list_option) as $domain) {
    	$domainlimitregex_list .= $domain.PHP_EOL;
    }
	$disabled = false;

	echo "<h3>Domain Limiter RegEx Settings</h3>";

	if ( !in_array( YOURLS_USER, $domainlimitregex_exempt_users ) ) {
		echo "<strong style='color:red;'>You are not authorized to edit this setting</strong>";
		$disabled = " readonly";
	}

	echo <<<HTML
	    <form method="post">
		<p>Please enter each URL on a new line</p>
		<textarea name="domainlimitregex_list" style="width:100%;min-height:7em;"{$disabled}>{$domainlimitregex_list}</textarea>
HTML;
		if(in_array( YOURLS_USER, $domainlimitregex_exempt_users )) echo "<button type='submit'>Save</button>";
}

// Update option in database
function domainlimitregex_config_update_option() {
    $list_array = explode(PHP_EOL, $_POST['domainlimitregex_list']);
    foreach ($list_array as $domain) {
    	if(trim($domain)!="")
    	$list[] = filter_var(trim($domain), FILTER_SANITIZE_URL);
    }

    if($list) {

        $jsonlist = json_encode( $list );

        if (yourls_get_option('domainlimitregex_list') !== false) {
            yourls_update_option('domainlimitregex_list', $jsonlist);
        } else {
            yourls_add_option('domainlimitregex_list', $jsonlist);
        }
    }
}
