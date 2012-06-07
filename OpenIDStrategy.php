<?php
/**
 * OpenID strategy for Opauth
 * 
 * Implemented with Mewp's LightOpenID Library,
 *   included at Vendor/lightopenid
 *   (https://gitorious.org/lightopenid/lightopenid)
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.OpenIDStrategy
 * @license      MIT License
 */

/**
 * OpenID strategy for Opauth
 * 
 * @package			Opauth.OpenIDStrategy
 */
class OpenIDStrategy extends OpauthStrategy{
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array();
	
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array();
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		// Refer to http://openid.net/specs/openid-attribute-properties-list-1_0-01.html if
		// you wish to overwrite these
		'required' => array(
			'contact/internet/email',
			'namePerson/first',
			'namePerson/last',
			'namePerson/friendly',
			'person/guid'
		),
		'optional' => array(
			'contact/phone',
			'contact/web',
			'media/image'
		)
	);
	
	public function __construct($strategy, $env){
		parent::__construct($strategy, $env);
		
		$parsed = parse_url($this->env['host']);
		require dirname(__FILE__).'/Vendor/lightopenid/openid.php';
		$this->openid = new LightOpenID($parsed['host']);
		$this->openid->required = $this->strategy['required'];
		$this->openid->optional = $this->strategy['optional'];
	}
	
	/**
	 * Ask for OpenID identifer
	 */
	public function request(){
		$identifier = 'yahoo.com';
		
		if (!$this->openid->mode){
			$this->openid->identity = $identifier;
			$this->redirect($this->openid->authUrl());
		}
		elseif ($this->openid->mode == 'cancel'){
			echo 'User has canceled authentication!';
	    }
		else {
			echo 'User ' . ($this->openid->validate() ? $this->openid->identity . ' has ' : 'has not ') . 'logged in.';
			print_r($this->openid->getAttributes());
		}
	}
}