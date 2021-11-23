/*
 * Copyright 2021 The Android Open Source Project
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

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Log;

/**
 * A job scheduler service responsible for performing Isolated Compilation when scheduled.
 *
 * @hide
 */
public class IsolatedCompilationJobService extends JobService {
    private static final String TAG = IsolatedCompilationJobService.class.getName();

    @Override
    public boolean onStartJob(JobParameters params) {
        Log.i(TAG, "starting job");

        // TODO(b/199147668): Implement

        return false; // Finished
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return false; // Don't reschedule
    }
}
