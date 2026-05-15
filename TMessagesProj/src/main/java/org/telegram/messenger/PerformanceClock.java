package org.telegram.messenger;

import com.google.android.exoplayer2.util.Log;

import java.util.Arrays;

public final class PerformanceClock {
    private static long timer_start;

    private static long[] measurements;
    private static int i;

    public static void init(int n) {
        measurements = new long[n];
        i = 0;
        timer_start = -1;
    }

    public static void StartClock() {
        if (timer_start != -1) {
            Log.e("MyTest", "Tried to start clock, but it has already been started!");
        }

        timer_start = System.currentTimeMillis();
    }

    public static void StopClock() {
        long timer_stop = System.currentTimeMillis();

        if (timer_start != -1 && measurements != null) {
            long diff = timer_stop - timer_start;

            measurements[i] = diff;
            i++;

            timer_start = -1;
        } else {
            Log.e("MyTest", "Tried to stop clock, but it has not been started!");
        }
    }

    public static void printMeasurements() {
        Log.d("MyTest", Arrays.toString(measurements));
    }
}
