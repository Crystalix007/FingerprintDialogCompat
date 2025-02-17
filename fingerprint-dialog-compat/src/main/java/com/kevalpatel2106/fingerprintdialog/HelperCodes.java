/*
 * Copyright 2018 Keval Patel
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance wit
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
 *  the specific language governing permissions and limitations under the License.
 */

package com.kevalpatel2106.fingerprintdialog;

import android.annotation.SuppressLint;
import android.hardware.fingerprint.FingerprintManager;
import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Created by Keval on 08/04/18.
 * Error codes to detect the error from the fingerprint authentication. This error codes are for the
 * errors which are recoverable. Fingerprint authentication won't terminate once the any of these
 * error code occurs.
 *
 * @author <a href="https://github.com/kevalpatel2106">kevalpatel2106</a>
 */
@SuppressWarnings("deprecation")
@SuppressLint("InlinedApi")
@Retention(RetentionPolicy.SOURCE)
@IntDef({
        FingerprintManager.FINGERPRINT_ACQUIRED_GOOD,
        FingerprintManager.FINGERPRINT_ACQUIRED_IMAGER_DIRTY,
        FingerprintManager.FINGERPRINT_ACQUIRED_INSUFFICIENT,
        FingerprintManager.FINGERPRINT_ACQUIRED_PARTIAL,
        FingerprintManager.FINGERPRINT_ACQUIRED_TOO_FAST,
        FingerprintManager.FINGERPRINT_ACQUIRED_TOO_SLOW,
})
public @interface HelperCodes {
}
