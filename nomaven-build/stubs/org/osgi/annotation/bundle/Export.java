package org.osgi.annotation.bundle;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS) @Target(ElementType.PACKAGE)
public @interface Export { String[] substitution() default {}; String[] attribute() default {}; }
