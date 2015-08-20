import io.dbmaster.testng.BaseToolTestNGCase
import org.testng.annotations.Test
import static org.testng.Assert.assertTrue;

public class PermissionReportIT extends BaseToolTestNGCase {
    @Test
    public void test() {
        def parameters = [:] 
        String result = tools.toolExecutor("permission-report", parameters).execute()
        assertTrue(result.contains("Server"), "Unexpected search results ${result}");
    }
}
