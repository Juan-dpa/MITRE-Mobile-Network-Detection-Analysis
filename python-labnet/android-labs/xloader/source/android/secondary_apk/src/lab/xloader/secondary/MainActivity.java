package lab.xloader.secondary;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(48, 48, 48, 48);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("Etapa secundaria inocua instalada");
        title.setTextColor(Color.rgb(30, 70, 120));
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);

        TextView detail = new TextView(this);
        detail.setText("Paquete: lab.xloader.secondary\n\nEsta aplicación no solicita permisos, no ejecuta servicios y no genera tráfico de red.");
        detail.setTextColor(Color.DKGRAY);
        detail.setTextSize(16);
        detail.setGravity(Gravity.CENTER);
        detail.setPadding(0, 32, 0, 0);

        root.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(detail, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(root);
    }
}
