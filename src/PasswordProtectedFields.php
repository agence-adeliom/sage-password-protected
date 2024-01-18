<?php

namespace Log1x\PasswordProtected;

use Log1x\AcfComposer\Partial;
use StoutLogic\AcfBuilder\FieldsBuilder;

/**
 * Password Protected
 */
class PasswordProtectedFields extends Partial
{
    /**
     * The partial field group.
     *
     * @return FieldsBuilder|array
     */
    public function fields(): FieldsBuilder|array
    {

        $config = (object) [
            'ui'      => 1,
            'wrapper' => ['width' => 30],
            'ip'      => $_SERVER['X-Forwarded-For'] ?? $_SERVER['REMOTE_ADDR'],
        ];

        $password = new FieldsBuilder('password_protected');

        $password
            ->addTab(__('Password Protection', 'sage-password-protected'), ['placement' => 'left', 'label' => __('Password Protection', 'sage-password-protected')]);

        $password
            ->addTrueFalse('password_protected', [ 'label' => __('Password Protection', 'sage-password-protected'), 'ui' => $config->ui])
            ->setInstructions(__('Enable site-wide password protection?', 'sage-password-protected'))

            ->addPassword('password',  ['label' => __('Password'), 'ui' => $config->ui])
            ->setInstructions(__('Enter the login password.', 'sage-password-protected'))
            ->conditional('password_protected', '==', '1')

            ->addTrueFalse('password_allow_ip_address', ['label' => __('Allow by IP Address', 'sage-password-protected'), 'ui' => $config->ui])
            ->setInstructions(__('Enable whitelisting users by their IP Address.', 'sage-password-protected'))
            ->conditional('password_protected', '==', '1')

            ->addRepeater('password_allowed_ip_addresses', ['label' => __('Allowed IP Addresses', 'sage-password-protected'), 'button_label' => __('Add IP Address', 'sage-password-protected')])
            ->conditional('password_protected', '==', '1')
            ->and('password_allow_ip_address', '==', '1')
            ->setInstructions(sprintf(__('Current IP Address: %s', 'sage-password-protected'), $config->ip))

            ->addText('ip_address', ['label' => __('IP Address', 'sage-password-protected'), 'placeholder' => $config->ip])
            ->setInstructions(__('The IP Address of the user to allow through password protection.', 'sage-password-protected'))

            ->addText('ip_address_comment', ['label' => __('Comment'), 'placeholder' => __('John Doe\'s Home', 'sage-password-protected')])
            ->setInstructions(__('A comment containing an identifier for this IP address. This is strictly for organization purposes.', 'sage-password-protected'))
            ->endRepeater()

            ->addTrueFalse('password_allow_users', ['label' => __('Allow for User', 'sage-password-protected'), 'ui' => $config->ui])
            ->setInstructions(__('Allow bypassing password protection while logged in as a user.', 'sage-password-protected'))
            ->conditional('password_protected', '==', '1')

            ->addTrueFalse('password_allow_administrators', ['label' => __('Allow for Administrator', 'sage-password-protected'),'ui' => $config->ui])
            ->conditional('password_protected', '==', '1')
            ->and('password_allow_users', '==', '0')
            ->setInstructions(__('Allow bypassing password protection while logged in as an administrator.', 'sage-password-protected'));

        return $password;
    }
}
