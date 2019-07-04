/*
 * Copyright (c) 2018. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package com.kevalpatel2106.fingerprintdialog;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.fragment.app.DialogFragment;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Created by Keval on 07/04/18.
 * Dialog that acts as the backport of {@link android.hardware.fingerprint.FingerprintDialog} for
 * android version below P.
 *
 * @author <a href="https://github.com/kevalpatel2106">kevalpatel2106</a>
 */
@SuppressWarnings("deprecation")
@TargetApi(Build.VERSION_CODES.M)
public class FingerprintDialogCompatV23 extends DialogFragment {
    // Keys of the arguments.
    private static final String ARG_TITLE = "arg_title";
    private static final String ARG_SUBTITLE = "arg_subtitle";
    private static final String ARG_NEGATIVE_BUTTON_TITLE = "arg_negative_button_title";
    private static final String ARG_DESCRIPTION = "arg_description";
    private static final String ARG_CRYPTO_OBJECT_GENERATOR = "arg_crypto_object_generator";

    /**
     * {@link Context} of the activity with witch this dialog is attached.
     */
    private Context mContext;

    /**
     * CryptoObjectGenerator to generate new crypto objects
     */
    private CryptoObjectGenerator mCryptoObjectGenerator;

    /**
     * Fingerprint scanning is currently running.
     */
    private boolean isScanning = false;
    /**
     * {@link android.widget.TextView} to display the fingerprint scanner status and errors.
     */
    private AppCompatTextView mStatusText;
    /**
     * {@link AuthenticationCallback} to notify the parent caller about the authentication status.
     */
    @SuppressWarnings("NullableProblems")
    @NonNull
    private AuthenticationCallback mCallback;
    /**
     * {@link CancellationSignal} for finger print authentication.
     */
    private CancellationSignal mCancellationSignal;

    private Runnable mStatusTextRunnable;

    /**
     * Create new instance of the {@link FingerprintDialogCompatV23}.
     *
     * @param title               Title of the dialog.
     * @param subtitle            Subtitle of the dialog. Only first two lines of the subtitle will
     *                            be displayed.
     * @param description         Description to display on the dialog. Only first four lines of the
     *                            description will be displayed.
     * @param negativeButtonTitle Title of the negative/cancel button on the dialog.
     * @param cryptoObjectGenerator The generator for new crypto objects
     * @return {@link FingerprintDialogCompatV23}
     */
    static FingerprintDialogCompatV23 createDialog(@NonNull String title,
                                                   @NonNull String subtitle,
                                                   @NonNull String description,
                                                   @NonNull String negativeButtonTitle,
                                                   @NonNull CryptoObjectGenerator cryptoObjectGenerator) {
        FingerprintDialogCompatV23 fingerprintDialogCompat = new FingerprintDialogCompatV23();

        //Set the arguments
        Bundle bundle = new Bundle();
        bundle.putString(ARG_TITLE, title);
        bundle.putString(ARG_SUBTITLE, subtitle);
        bundle.putString(ARG_DESCRIPTION, description);
        bundle.putString(ARG_NEGATIVE_BUTTON_TITLE, negativeButtonTitle);
        bundle.putSerializable(ARG_CRYPTO_OBJECT_GENERATOR, cryptoObjectGenerator);
        fingerprintDialogCompat.setArguments(bundle);

        return fingerprintDialogCompat;
    }

    /**
     * Set the {@link AuthenticationCallback} for notifying the status of fingerprint authentication.
     * Application must have to call {@link #createDialog(String, String, String, String)}.
     *
     * @param callback {@link AuthenticationCallback}
     */
    public void setAuthenticationCallback(@NonNull final AuthenticationCallback callback) {
        mCallback = callback;
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        // No call for super(). Bug on API Level > 11.
        // https://stackoverflow.com/a/10261449
    }

    @Override
    public void onAttach(final Context context) {
        super.onAttach(context);
        mContext = context;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        return LayoutInflater.from(getContext())
                .inflate(R.layout.fingerprint_compat_dialog, container, false);
    }

    @Override
    public void onStart() {
        super.onStart();
        Window window = getDialog().getWindow();
        if (window == null) return;

        //Display the dialog full width of the screen
        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        window.setLayout(getResources().getDisplayMetrics().widthPixels,
                WindowManager.LayoutParams.WRAP_CONTENT);

        //Display the at the bottom of the screen
        WindowManager.LayoutParams wlp = window.getAttributes();
        wlp.gravity = Gravity.BOTTOM;
        wlp.windowAnimations = R.style.DialogAnimation;
        wlp.flags &= ~WindowManager.LayoutParams.FLAG_DIM_BEHIND;
        window.setAttributes(wlp);
    }

    @Override
    public void onResume() {
        super.onResume();

        //Check if the device has fingerprint supported hardware.
        if (FingerprintUtils.isSupportedHardware(mContext)) {

            //Device has supported hardware. Start fingerprint authentication.
            startAuth();
        } else {
            mCallback.fingerprintAuthenticationNotSupported();
            closeDialog();
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        stopAuthIfRunning();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        stopAuthIfRunning();
    }

    @Override
    public void onDetach() {
        super.onDetach();
        stopAuthIfRunning();
    }

    @Override
    public void onViewCreated(@NonNull final View view, @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (getArguments() == null) throw new IllegalStateException("No arguments found.");

        //Set the title
        if (getArguments().containsKey(ARG_TITLE)) {
            final AppCompatTextView titleTv = view.findViewById(R.id.title_tv);
            titleTv.setText(getArguments().getString(ARG_TITLE));
            titleTv.setSelected(true);
        } else {
            throw new IllegalStateException("Title cannot be null.");
        }

        //Set the subtitle
        if (getArguments().containsKey(ARG_SUBTITLE)) {
            final AppCompatTextView subtitleTv = view.findViewById(R.id.subtitle_tv);
            subtitleTv.setText(getArguments().getString(ARG_SUBTITLE));
        } else {
            throw new IllegalStateException("Subtitle cannot be null.");
        }

        //Set the description
        if (getArguments().containsKey(ARG_DESCRIPTION)) {
            final AppCompatTextView descriptionTv = view.findViewById(R.id.description_tv);
            descriptionTv.setText(getArguments().getString(ARG_DESCRIPTION));
        } else {
            throw new IllegalStateException("Description cannot be null.");
        }

        //Set the negative button text
        if (getArguments().containsKey(ARG_NEGATIVE_BUTTON_TITLE)) {

            final AppCompatButton negativeButton = view.findViewById(R.id.negative_btn);
            negativeButton.setText(getArguments().getString(ARG_NEGATIVE_BUTTON_TITLE));
            negativeButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(final View view) {
                    //Close the dialog
                    closeDialog();
                }
            });
        } else {
            throw new IllegalStateException("Description cannot be null.");
        }

        if (getArguments().containsKey(ARG_CRYPTO_OBJECT_GENERATOR)) {
            mCryptoObjectGenerator = (CryptoObjectGenerator) getArguments().getSerializable(ARG_CRYPTO_OBJECT_GENERATOR);
        } else {
            throw new IllegalStateException("Crypto object generator cannot be null");
        }

        //Set the application drawable.
        try {
            AppCompatImageView appIconIv = view.findViewById(R.id.app_icon_iv);
            appIconIv.setImageDrawable(getApplicationIcon(mContext));
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage());
        }

        //Status text.
        mStatusText = view.findViewById(R.id.fingerprint_status_tv);
    }



    /**
     * Start the finger print authentication by enabling the finger print sensor.
     * Note: Use this function in the onResume() of the activity/fragment. Never forget to call
     * {@link #stopAuthIfRunning()} in onPause() of the activity/fragment.
     */
    @TargetApi(Build.VERSION_CODES.M)
    private void startAuth() {
        if (isScanning) stopAuthIfRunning();
        final FingerprintManager fingerprintManager = (FingerprintManager) mContext.getSystemService(Context.FINGERPRINT_SERVICE);

        //Cannot access the fingerprint manager.
        if (fingerprintManager == null) {
            mCallback.fingerprintAuthenticationNotSupported();
            return;
        }

        //No fingerprint enrolled.
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            mCallback.hasNoFingerprintEnrolled();
            return;
        }

        final FingerprintManager.CryptoObject cryptoObject = mCryptoObjectGenerator.getFingerprintCryptoObject();
        if (cryptoObject != null) {
            final FingerprintManager.AuthenticationCallback authCallback = new FingerprintManager.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errMsgId, CharSequence errString) {
                    displayStatusText(errString.toString(), true);

                    switch (errMsgId) {
                        case FingerprintManager.FINGERPRINT_ERROR_CANCELED:
                        case FingerprintManager.FINGERPRINT_ERROR_USER_CANCELED:
                            mCallback.authenticationCanceledByUser();
                            break;
                        case FingerprintManager.FINGERPRINT_ERROR_HW_NOT_PRESENT:
                        case FingerprintManager.FINGERPRINT_ERROR_HW_UNAVAILABLE:
                            mCallback.fingerprintAuthenticationNotSupported();
                            break;
                        default:
                            mCallback.onAuthenticationError(errMsgId, errString);
                    }
                }

                @Override
                public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                    displayStatusText(helpString.toString(), false);
                    mCallback.onAuthenticationHelp(helpMsgId, helpString);
                }

                @Override
                public void onAuthenticationFailed() {
                    displayStatusText(getString(R.string.fingerprint_not_recognised), false);
                    mCallback.onAuthenticationFailed();
                }

                @Override
                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                    mCallback.onAuthenticationSucceeded();
                    closeDialog();
                }
            };

            mCancellationSignal = new CancellationSignal();
            //noinspection MissingPermission
            fingerprintManager.authenticate(cryptoObject,
                    mCancellationSignal,
                    0,
                    authCallback,
                    new Handler(Looper.getMainLooper()));
        } else {
            //Cannot access the secure keystore.
            mCallback.fingerprintAuthenticationNotSupported();
            closeDialog();
        }
    }

    /**
     * Stop the finger print authentication.
     */
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void stopAuthIfRunning() {
        if (mStatusTextRunnable != null) {
            new Handler().removeCallbacks(mStatusTextRunnable);
            mStatusTextRunnable = null;
        }

        if (mCancellationSignal != null) {
            isScanning = false;
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }

    private void closeDialog() {
        stopAuthIfRunning();
        dismiss();
    }

    /**
     * Display the text in the {@link #mStatusText} for 1 second.
     *
     * @param status    Status text to display.
     * @param isDismiss True if the dialog should dismiss after status text displayed.
     */
    private void displayStatusText(@NonNull final String status,
                                   final boolean isDismiss) {

        mStatusText.setText(status);
        mStatusTextRunnable = new Runnable() {
            @Override
            public void run() {

                if (getDialog() != null && getDialog().isShowing()) {
                    mStatusText.setText("");
                    if (isDismiss) closeDialog();
                }
            }
        };
        new Handler().postDelayed(mStatusTextRunnable, 1000 /* 1 seconds */);
    }

    /**
     * Get the application icon.
     *
     * @param context {@link Context} of the caller.
     * @return {@link Drawable} icon of the application.
     * @throws PackageManager.NameNotFoundException If the package npt found.
     */
    @NonNull
    private Drawable getApplicationIcon(@NonNull final Context context) throws PackageManager.NameNotFoundException {
        try {
            return context.getPackageManager().getApplicationIcon(context.getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            throw e;
        }
    }
}
