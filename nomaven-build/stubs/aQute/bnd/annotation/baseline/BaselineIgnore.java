package aQute.bnd.annotation.baseline;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.PACKAGE, ElementType.METHOD, ElementType.FIELD, ElementType.CONSTRUCTOR})
public @interface BaselineIgnore { String value(); }
