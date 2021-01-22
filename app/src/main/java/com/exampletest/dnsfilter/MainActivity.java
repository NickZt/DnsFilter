package com.exampletest.dnsfilter;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;

import com.exampletest.dnsfilter.dns.LocalVpnService;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.util.Log;
import android.view.View;

import android.view.Menu;
import android.view.MenuItem;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity implements LocalVpnService.onStatusChangedListener {

    private static final String TAG = "dnshttp";
    public static final int REQUEST_CODE = 221;
    private static final int PERMISSIONS_REQUEST = 122;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (!allPermissionsGranted()) {
            getRuntimePermissions();
        }
        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (LocalVpnService.getService() != null) {
                    Log.d(TAG, "onClick() DNS filter service is running!");
                    Snackbar.make(view, "  VPN is running!", Snackbar.LENGTH_LONG)
                            .setAction("Disconnect", v -> {
                                LocalVpnService.getInstance().disconnectVPN();
                                stopService(LocalVpnService.getService());
                                System.runFinalization();
                                System.exit(0);
                            }).show();
                    //Logger.getLogger().message("Attached already running Service!");
                    return;
                } else {
                    Snackbar.make(view, "Connect  VPN  ", Snackbar.LENGTH_LONG)
                            .setAction("Connect", v -> {
                                Intent intent = null;
                                intent = LocalVpnService.prepare(getBaseContext());
                                if (intent != null) {
//                                    Ask for  permission for start VPN
                                    startActivityForResult(intent, REQUEST_CODE);
                                } else {
                                    startVPNService();
//                                    Snackbar.make(view, "Start unsuccessfully  ", Snackbar.LENGTH_LONG).show();
                                }
                            }).show();
                }
            }
        });


        LocalVpnService.addOnStatusChangedListener(this);
    }

    private boolean allPermissionsGranted() {
        for (String permission : getRequiredPermissions()) {
            if (!isPermissionGranted(this, permission)) {
                return false;
            }
        }
        return true;
    }

    private void getRuntimePermissions() {
        List<String> allNeededPermissions = new ArrayList<>();
        for (String permission : getRequiredPermissions()) {
            if (!isPermissionGranted(this, permission)) {
                allNeededPermissions.add(permission);
            }
        }

        if (!allNeededPermissions.isEmpty()) {
            ActivityCompat.requestPermissions(
                    this, allNeededPermissions.toArray(new String[0]), PERMISSIONS_REQUEST);
        }
    }

    public static boolean isPermissionGranted(Context context, String permission) {
        if (ContextCompat.checkSelfPermission(context, permission)
                == PackageManager.PERMISSION_GRANTED) {
            Log.i(TAG, " TODEL Permission granted: " + permission);
            return true;
        }
        Log.i(TAG, "Permission NOT granted: " + permission);
        return false;
    }

    private String[] getRequiredPermissions() {
        try {
            PackageInfo info =
                    this.getPackageManager()
                            .getPackageInfo(this.getPackageName(), PackageManager.GET_PERMISSIONS);
            String[] ps = info.requestedPermissions;
            if (ps != null && ps.length > 0) {
                return ps;
            } else {
                return new String[0];
            }
        } catch (Exception e) {
            return new String[0];
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        Log.d(" TODEL ", "onRequestPermissionsResult() called with: requestCode = [" + requestCode + "], " +
                "permissions = [" + permissions + "], grantResults = [" + grantResults + "]");
        if (allPermissionsGranted()) {
//            initView();
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        Log.d(TAG, "onActivityResult() called with: requestCode = [" + requestCode + "], resultCode = [" + resultCode + "], data = [" + data + "]");
        if (requestCode == REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                Log.d(TAG, "onActivityResult() called with:resultCode == RESULT_OK requestCode = [" + requestCode + "], resultCode = [" + resultCode + "], data = [" + data + "]");
                startVPNService();

            }
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void startVPNService() {
        Intent intent = new Intent(this, LocalVpnService.class);
        intent.putExtra("PROXY_URL", "https://dns.google/");
        startService(intent);
//        startService(LocalVpnService.getService());
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onStatusChanged(String status, Boolean isRunning) {
        Log.d(TAG, "onStatusChanged() called with: status = [" + status + "], isRunning = [" + isRunning + "]");
    }

    @Override
    public void onLogReceived(String logString) {
        Log.i(TAG + "-VPNLog", logString);
    }

    @Override
    public void onConnectionChanged(boolean isConn) {
        Log.d(TAG, "onConnectionChanged() called with: isConn = [" + isConn + "]");
    }

    @Override
    public void onConnectionError() {
        Log.d(TAG, "onConnectionError() called");
    }
}