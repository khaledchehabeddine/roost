# JNA's native code and reflection find these classes, fields and methods by name.
-keep class com.sun.jna.** { *; }
-keep class * extends com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
# JNA's desktop-only AWT helpers reference classes Android doesn't have.
-dontwarn java.awt.**
