/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.compos;

import android.annotation.IntDef;
import android.os.SystemClock;
import android.util.Log;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * A class that handles reporting metrics relating to Isolated Compilation to statsd.
 *
 * @hide
 */
class IsolatedCompilationMetrics {
    private static final String TAG = IsolatedCompilationMetrics.class.getName();

    // TODO(b/218525257): Move the definition of these enums to atoms.proto
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({RESULT_SUCCESS, RESULT_UNKNOWN_FAILURE, RESULT_FAILED_TO_START, RESULT_JOB_CANCELED,
            RESULT_COMPILATION_FAILED, RESULT_UNEXPECTED_COMPILATION_RESULT, RESULT_COMPOSD_DIED})
    public @interface CompilationResult {}

    public static final int RESULT_SUCCESS = 0;
    public static final int RESULT_UNKNOWN_FAILURE = 1;
    public static final int RESULT_FAILED_TO_START = 2;
    public static final int RESULT_JOB_CANCELED = 3;
    public static final int RESULT_COMPILATION_FAILED = 4;
    public static final int RESULT_UNEXPECTED_COMPILATION_RESULT = 5;
    public static final int RESULT_COMPOSD_DIED = 6;

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({SCHEDULING_SUCCESS, SCHEDULING_FAILURE})
    public @interface ScheduleJobResult {}

    public static final int SCHEDULING_SUCCESS = 0;
    public static final int SCHEDULING_FAILURE = 1;

    private long mCompilationStartTimeMs = 0;

    public static void onCompilationScheduled(@ScheduleJobResult int result) {
        // TODO(b/218525257): write to ArtStatsLog instead of logcat
        // ArtStatsLog.write(ArtStatsLog.ISOLATED_COMPILATION_SCHEDULED, result);
        Log.i(TAG, "ISOLATED_COMPILATION_SCHEDULED: " + result);
    }

    public void onCompilationStarted() {
        mCompilationStartTimeMs = SystemClock.elapsedRealtime();
    }

    public void onCompilationEnded(@CompilationResult int result) {
        long compilationTime = mCompilationStartTimeMs == 0 ? -1
                : SystemClock.elapsedRealtime() - mCompilationStartTimeMs;
        mCompilationStartTimeMs = 0;

        // TODO(b/218525257): write to ArtStatsLog instead of logcat
        // ArtStatsLog.write(ArtStatsLog.ISOLATED_COMPILATION_ENDED, result, compilationTime);
        Log.i(TAG, "ISOLATED_COMPILATION_ENDED: " + result + ", " + compilationTime);
    }
}
