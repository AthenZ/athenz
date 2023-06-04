import ch.qos.logback.core.OutputStreamAppender;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;

public class ServiceOutputStreamAppender<E> extends OutputStreamAppender<E> {
    public ServiceOutputStreamAppender() {
        setOutputStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                BufferedWriter responseWriter = GcfSiaTest.threadLocalResponseWriter.get();
                if (responseWriter != null) {
                    responseWriter.write(b);
                }
            }
        });
    }
}
