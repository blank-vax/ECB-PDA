import java.io.IOException;

public interface PDA {
    void TA_init() throws IOException;

    void entity_generation() throws IOException;

    void registration() throws IOException;

    void report_generation() throws IOException;

    void report_aggregation() throws IOException;

    void report_read() throws IOException;

    void response() throws IOException;
}
