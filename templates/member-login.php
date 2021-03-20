<?php

$domain = 'Custom_User_Flow';

?>

<div id="login">
    <?php if ( $attributes['show_title'] ) : ?>
    <h2><?php _e( 'Sign In', $domain); ?></h2>
    <?php endif; ?>

    <!-- Show errors if there are any -->
    <?php if ( count( $attributes['errors'] ) ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
    <p class="login-error"><?php echo $error; ?></p>
    <?php endforeach; ?>
    <?php endif; ?>

    <!-- Show logged out message if user just logged out -->
    <?php if ( $attributes['logged_out'] ) : ?>
    <p class="login-info">
        <?php _e( 'You have signed out. Would you like to sign in again?', $domain); ?>
    </p>
    <?php endif; ?>

    <?php
        wp_login_form(array(
            'label_username' => __( 'Email', $domain),
            'label_log_in' => __( 'Sign In', $domain),
            'redirect' => $attributes['redirect'],
        ));
    ?>

    <a class="forgot-password" href="<?php echo wp_lostpassword_url(); ?>">
        <?php _e( 'Forgot your password?', $domain); ?>
    </a>
</div>