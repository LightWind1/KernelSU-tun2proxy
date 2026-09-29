import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Looper;
import java.lang.reflect.Method;
import java.util.List;

// Runs as root via app_process. The Go backend remains authoritative for
// package names and UIDs; this helper only supplies human-readable labels.
public final class AppLabels {
    public static void main(String[] args) {
        try {
            Looper.prepare();
            Class<?> cls = Class.forName("android.app.ActivityThread");
            Method systemMain = cls.getDeclaredMethod("systemMain");
            systemMain.setAccessible(true);
            Object thread = systemMain.invoke(null);
            Method getSystemContext = cls.getDeclaredMethod("getSystemContext");
            getSystemContext.setAccessible(true);
            Context context = (Context) getSystemContext.invoke(thread);
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> apps = pm.getInstalledPackages(0);
            for (PackageInfo app : apps) {
                ApplicationInfo info = app.applicationInfo;
                if (info == null || app.packageName == null) continue;
                CharSequence label = info.loadLabel(pm);
                if (label == null) continue;
                String clean = label.toString().replace('\t', ' ').replace('\n', ' ').replace('\r', ' ').trim();
                if (!clean.isEmpty()) System.out.println(app.packageName + "\t" + clean);
            }
        } catch (Throwable e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            System.err.println("App label lookup unavailable: " + cause.getClass().getSimpleName());
            System.exit(1);
        }
    }
}
