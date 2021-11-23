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

import static java.util.Objects.requireNonNull;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.system.composd.ICompilationTask;
import android.system.composd.ICompilationTaskCallback;
import android.system.composd.IIsolatedCompilationService;
import android.util.Log;

import java.util.concurrent.atomic.AtomicReference;

/**
 * A job scheduler service responsible for performing Isolated Compilation when scheduled.
 *
 * @hide
 */
public class IsolatedCompilationJobService extends JobService {
    private static final String TAG = IsolatedCompilationJobService.class.getName();

    private final AtomicReference<CompilationJob> mCurrentJob = new AtomicReference<>();

    @Override
    public boolean onStartJob(JobParameters params) {
        Log.i(TAG, "starting job");

        CompilationJob oldJob = mCurrentJob.getAndSet(null);
        if (oldJob != null) {
            // This should probably never happen, but just in case
            oldJob.stop();
        }

        // This function (and onStopJob) are only ever called on the main thread, so we don't have
        // to worry about two starts at once, or start and stop happening at once. But onCompletion
        // can be called on any thread, so we need to be careful with that.

        CompilationCallback callback = new CompilationCallback() {
            @Override
            public void onSuccess() {
                onCompletion(params, true);
            }

            @Override
            public void onFailure() {
                onCompletion(params, false);
            }
        };
        CompilationJob newJob = new CompilationJob(callback);
        mCurrentJob.set(newJob);

        try {
            // This can take some time - we need to start up a VM - so we do it on a separate
            // thread. This thread exits as soon as the compilation Ttsk has been started (or
            // there's a failure), and then compilation continues in composd and the VM.
            new Thread("IsolatedCompilationJob_starter") {
                @Override
                public void run() {
                    newJob.start();
                }
            }.start();
        } catch (RuntimeException e) {
            Log.e(TAG, "Starting CompilationJob failed", e);
            return false; // We're finished
        }
        return true; // Job is running in the background
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        CompilationJob job = mCurrentJob.getAndSet(null);
        if (job == null) {
            return false; // No need to reschedule, we'd finished
        } else {
            job.stop();
            return true; // We didn't get to finish, please re-schedule
        }
    }

    void onCompletion(JobParameters params, boolean succeeded) {
        Log.i(TAG, "onCompletion, succeeded=" + succeeded);

        CompilationJob job = mCurrentJob.getAndSet(null);
        if (job == null) {
            // No need to call jobFinished if we've been told to stop.
            return;
        }
        // On success we don't need to reschedule.
        // On failure we could reschedule, but that could just use a lot of resources and still
        // fail; instead we just let odsign do compilation on reboot if necessary.
        jobFinished(params, /*wantReschedule=*/ false);
    }

    interface CompilationCallback {
        void onSuccess();

        void onFailure();
    }

    static class CompilationJob extends ICompilationTaskCallback.Stub
            implements IBinder.DeathRecipient {
        private final AtomicReference<ICompilationTask> mTask = new AtomicReference<>();
        private final CompilationCallback mCallback;
        private volatile boolean mStopRequested = false;
        private volatile boolean mCanceled = false;

        CompilationJob(CompilationCallback callback) {
            mCallback = requireNonNull(callback);
        }

        void start() {
            IBinder binder = ServiceManager.waitForService("android.system.composd");
            IIsolatedCompilationService composd =
                    IIsolatedCompilationService.Stub.asInterface(binder);

            if (composd == null) {
                throw new IllegalStateException("Unable to find composd service");
            }

            try {
                ICompilationTask composTask = composd.startTestCompile(this);
                mTask.set(composTask);
                composTask.asBinder().linkToDeath(this, 0);
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            }

            if (mStopRequested) {
                // We were asked to stop while we were starting the task. We need to
                // cancel it now, since we couldn't before.
                cancelTask();
            }
        }

        void stop() {
            mStopRequested = true;
            cancelTask();
        }

        private void cancelTask() {
            ICompilationTask task = mTask.getAndSet(null);
            if (task != null) {
                mCanceled = true;
                Log.i(TAG, "Cancelling task");
                try {
                    task.cancel();
                } catch (RuntimeException | RemoteException e) {
                    // If canceling failed we'll assume it means that the task has already failed;
                    // there's nothing else we can do anyway.
                    Log.w(TAG, "Failed to cancel CompilationTask", e);
                }
            }
        }

        @Override
        public void binderDied() {
            onFailure();
        }

        @Override
        public void onSuccess() {
            mTask.set(null);
            if (!mCanceled) {
                mCallback.onSuccess();
            }
        }

        @Override
        public void onFailure() {
            mTask.set(null);
            if (!mCanceled) {
                mCallback.onFailure();
            }
        }
    }
}
