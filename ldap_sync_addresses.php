<?php
/**
 * LDAP Sync Adresses
 *
 * Syncs users identities with addresses from ldap
 * Based on "New user identity" by Kris Steinhoff
 *
 * This plugin requires that a working public_ldap directory be configured.
 *
 * @author Kris Steinhoff
 * @author Philipp Dieter <philipp.dieter@datentonne.net>
 * @license GNU GPLv3+
 */
class ldap_sync_addresses extends rcube_plugin
{
    public $task = 'login';

    private $rc;
    private $ldap;

    /**
     * Plugin initialization. API hooks binding.
     */
    function init()
    {
        $this->rc = rcmail::get_instance();

        $this->add_hook('login_after', [$this, 'login_after']);

    }

    /**
     * 'user_create' hook handler.
     */
    function lookup_user_name($args)
    {
        return $args;
    }

    /**
     * 'login_after' hook handler. This is where we create identities for
     * all user email addresses.
     */
    function login_after($args)
    {
        $this->load_config();

        $identities = $this->rc->user->list_emails();
        $email_list = [];

        if ($this->init_ldap(
            $this->rc->user->data['username'],
            $this->rc->user->data['mail_host']
        )) {
            $results = $this->ldap->search(
                'uid',
                $this->rc->user->data['username'],
                true
            );
            $data = [];
            if (count($results->records) == 1) {
                $user       = $results->records[0];
                $user_firstname  = is_array($user['firstname'])
                    ? $user['firstname'][0]
                    : $user['firstname'];
                $user_lastname  = is_array($user['surname'])
                    ? $user['surname'][0]
                    : $user['surname'];
                $user_email = is_array($user['email'])
                    ? $user['email'][0]
                    : $user['email'];
                $data['user_name']  = $user_firstname . ' ' . $user_lastname;
                $data['email_list'] = [];
                if (empty($data['user_email']) && strpos($user_email, '@')) {
                    $data['user_email'] = rcube_utils::idn_to_ascii($user_email);
                }
                if (!empty($data['user_email'])) {
                    $data['email_list'][] = $data['user_email'];
                }
                foreach (array_keys($user) as $key) {
                    if (!preg_match('/^(email|aliases)($|:)/', $key)) {
                        continue;
                    }
                    foreach ((array) $user[$key] as $alias) {
                        if (strpos($alias, '@')) {
                            $data['email_list'][] = rcube_utils::idn_to_ascii($alias);
                        }
                    }
                }
                $data['email_list'] = array_unique($data['email_list']);
            }
        }

        if (empty($data['email_list'])) {
            return $args;
        }

        $identities_to_delete = $identities;

        foreach ((array) $data['email_list'] as $email) {
            foreach ($identities as $identity_i => $identity) {
                if ($identity['email'] == $email) {
                    unset($identities_to_delete[$identity_i]);
                    continue 2;
                }
            }

            $standard = 0;
            if ($email == $data['user_email']) {
                $standard = 1;
            }

            $plugin = $this->rc->plugins->exec_hook('identity_create', [
                'login'  => true,
                'record' => [
                    'user_id'  => $this->rc->user->ID,
                    'standard' => $standard,
                    'email'    => $email,
                    'name'     => $data['user_name']
                ],
            ]);

            if (!$plugin['abort'] && !empty($plugin['record']['email'])) {
                $this->rc->user->insert_identity($plugin['record']);
            }
        }

        foreach ((array) $identities_to_delete as $identity) {
            $this->rc->user->delete_identity($identity['identity_id']);
        }

        return $args;
    }

    /**
     * Initialize LDAP backend connection
     */
    private function init_ldap($host, $user)
    {
        if ($this->ldap) {
            return $this->ldap->ready;
        }

        $this->load_config();

        $addressbook = $this->rc->config->get('ldap_sync_addresses_addressbook');

        $ldap_config = (array)$this->rc->config->get('ldap_public');

        $debug  = $this->rc->config->get('ldap_debug');
        $domain = $this->rc->config->mail_domain($host);
        $props  = $ldap_config[$addressbook];

        $this->ldap = new ldap_sync_addresses_ldap_backend($props, $debug, $domain, $match);

        return $this->ldap->ready;
    }
}

class ldap_sync_addresses_ldap_backend extends rcube_ldap
{
    function __construct($p, $debug, $mail_domain, $search)
    {
        parent::__construct($p, $debug, $mail_domain);
        $this->prop['search_fields'] = (array) $search;
    }
}
