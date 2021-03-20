<div id="signup" class="widecolumn">
    <?php if ( $attributes['show_title'] ) : ?>
    <h3><?php _e( 'Register', 'Custom_User_Flow' ); ?></h3>
    <?php endif; ?>

    <?php if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
    <p class="login-error">
        <?php echo $error; ?>
    </p>
    <?php endforeach; ?>
    <?php endif; ?>


    <?php if ( $attributes['registered'] ) : ?>
    <p class="login-info">
        <?php
            printf(
                __( 'You have successfully registered to <strong>%s</strong>. We have emailed your password to the email address you entered.', 'personalize-login' ),
                get_bloginfo( 'name' )
            );
        ?>
    </p>
    <?php endif; ?>


    <form id="signupform" action="<?php echo wp_registration_url(); ?>" method="post">
        <p class="form-row">
            <label for="email"><?php _e( 'Email', 'Custom_User_Flow' ); ?> <strong>*</strong></label>
            <input type="text" name="email" id="email">
        </p>

        <p class="form-row">
            <label for="first_name"><?php _e( 'First name', 'Custom_User_Flow' ); ?></label>
            <input type="text" name="first_name" id="first_name">
        </p>

        <p class="form-row">
            <label for="last_name"><?php _e( 'Last name', 'Custom_User_Flow' ); ?></label>
            <input type="text" name="last_name" id="last_name">
        </p>

        <p class="form-row">
            <small>
                <?php _e( 'Note: Your password will be generated automatically and sent to your email address.', 'Custom_User_Flow' ); ?>
            </small>
        </p>

        <?php if ( $attributes['recaptcha_site_key'] ) : ?>
        <p class="recaptcha-container">
        <div class="g-recaptcha" data-sitekey="<?php echo $attributes['recaptcha_site_key']; ?>"></div>
        </p>
        <?php endif; ?>

        <p class="signup-submit">
            <input type="submit" name="submit" class="register-button"
                value="<?php _e( 'Register', 'Custom_User_Flow' ); ?>" />
        </p>
    </form>
</div>