package aQute.bnd.annotation.jpms;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.PACKAGE})
public @interface ExportTo { String[] value(); }
