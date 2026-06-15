using System.Diagnostics;

public class ReportRunner
{
    public void Run(string cmd)
    {
        var psi = new ProcessStartInfo("/bin/sh", $"-c {cmd}");
    }
}
