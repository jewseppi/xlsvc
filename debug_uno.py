import logging
import time
import subprocess
import socket
import psutil
import uno
from com.sun.star.connection import NoConnectException

logger = logging.getLogger(__name__)

def check_libreoffice_process():
    """Check if LibreOffice is running"""
    logger.info("=== Checking LibreOffice Process ===")
    
    libreoffice_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if any('soffice' in str(item).lower() or 'libreoffice' in str(item).lower() 
                   for item in [proc.info['name']] + (proc.info['cmdline'] or [])):
                libreoffice_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': proc.info['cmdline']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    logger.info(f"Found {len(libreoffice_processes)} LibreOffice processes:")
    for proc in libreoffice_processes:
        logger.info(f"  PID {proc['pid']}: {proc['name']} - {proc['cmdline']}")
    
    return len(libreoffice_processes) > 0

def check_port_availability(host='localhost', port=2002):
    """Check if the UNO port is available"""
    logger.info(f"=== Checking Port {port} ===")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            logger.info(f"Port {port} is OPEN and accepting connections")
            return True
        else:
            logger.warning(f"Port {port} is CLOSED or not accepting connections")
            return False
    except Exception as e:
        logger.error(f"Error checking port {port}: {e}")
        return False
    finally:
        sock.close()

def start_libreoffice_with_retry(max_retries=3, wait_time=10):
    """Start LibreOffice with retries and better error handling"""
    logger.info("=== Starting LibreOffice with Retry Logic ===")
    
    # Kill any existing LibreOffice processes first
    kill_existing_libreoffice()
    
    for attempt in range(max_retries):
        logger.info(f"Attempt {attempt + 1}/{max_retries} to start LibreOffice")
        
        try:
            # Start LibreOffice
            cmd = [
                "libreoffice",
                "--headless",
                "--accept=socket,host=localhost,port=2002;urp;",
                "--norestore",
                "--invisible",
                "--nocrashreport",
                "--nodefault",
                "--nolockcheck"
            ]
            
            logger.info(f"Starting with command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=None
            )
            
            logger.info(f"LibreOffice process started with PID: {process.pid}")
            
            # Wait and check if it's actually running
            for check in range(wait_time):
                time.sleep(1)
                
                # Check if process is still alive
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    logger.error(f"LibreOffice process died early!")
                    logger.error(f"STDOUT: {stdout.decode()}")
                    logger.error(f"STDERR: {stderr.decode()}")
                    break
                
                # Check if port is open
                if check_port_availability():
                    logger.info(f"LibreOffice ready after {check + 1} seconds")
                    return process
                
                logger.info(f"Waiting for LibreOffice... ({check + 1}/{wait_time})")
            
            # If we get here, LibreOffice didn't start properly
            logger.warning(f"LibreOffice didn't become ready within {wait_time} seconds")
            process.terminate()
            time.sleep(2)
            
        except FileNotFoundError:
            logger.error("LibreOffice command not found!")
            return None
        except Exception as e:
            logger.error(f"Error starting LibreOffice: {e}")
    
    logger.error(f"Failed to start LibreOffice after {max_retries} attempts")
    return None

def kill_existing_libreoffice():
    """Kill any existing LibreOffice processes"""
    logger.info("=== Killing Existing LibreOffice Processes ===")
    
    killed_count = 0
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if any('soffice' in str(item).lower() or 'libreoffice' in str(item).lower() 
                   for item in [proc.info['name']] + (proc.info['cmdline'] or [])):
                logger.info(f"Killing process {proc.info['pid']}: {proc.info['name']}")
                proc.terminate()
                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Couldn't kill process: {e}")
    
    if killed_count > 0:
        logger.info(f"Killed {killed_count} LibreOffice processes")
        time.sleep(3)  # Give time for cleanup
    else:
        logger.info("No existing LibreOffice processes found")

def test_uno_connection_with_timeout():
    """Test UNO connection with various timeout settings"""
    logger.info("=== Testing UNO Connection ===")
    
    timeouts = [5, 10, 30, 60]  # seconds
    
    for timeout in timeouts:
        logger.info(f"Testing UNO connection with {timeout}s timeout...")
        
        try:
            # Set socket timeout
            import socket
            socket.setdefaulttimeout(timeout)
            
            # Get the local context
            localContext = uno.getComponentContext()
            
            # Get the service manager
            resolver = localContext.ServiceManager.createInstanceWithContext(
                "com.sun.star.bridge.UnoUrlResolver", localContext
            )
            
            # Try to connect with timeout
            start_time = time.time()
            context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
            connect_time = time.time() - start_time
            
            logger.info(f"✅ UNO connection successful in {connect_time:.2f}s (timeout: {timeout}s)")
            
            # Test desktop creation
            desktop = context.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", context
            )
            logger.info("✅ Desktop service created successfully")
            
            return desktop, context
            
        except Exception as e:
            logger.error(f"❌ UNO connection failed with {timeout}s timeout: {e}")
            continue
    
    logger.error("❌ All UNO connection attempts failed")
    return None, None

def process_excel_with_detailed_logging(input_path, output_path):
    """Process Excel file with comprehensive logging"""
    logger.info(f"=== Processing Excel File ===")
    logger.info(f"Input: {input_path}")
    logger.info(f"Output: {output_path}")
    
    # Step 1: Check environment
    logger.info("Step 1: Checking environment...")
    if not check_libreoffice_process():
        logger.warning("No LibreOffice process found")
    
    if not check_port_availability():
        logger.warning("UNO port not available")
    
    # Step 2: Start LibreOffice if needed
    logger.info("Step 2: Starting LibreOffice...")
    process = start_libreoffice_with_retry()
    if not process:
        logger.error("Failed to start LibreOffice")
        return False
    
    # Step 3: Test UNO connection
    logger.info("Step 3: Testing UNO connection...")
    desktop, context = test_uno_connection_with_timeout()
    if not desktop:
        logger.error("Failed to establish UNO connection")
        process.terminate()
        return False
    
    try:
        # Step 4: Load document
        logger.info("Step 4: Loading document...")
        file_url = uno.systemPathToFileUrl(os.path.abspath(input_path))
        logger.info(f"File URL: {file_url}")
        
        start_time = time.time()
        document = desktop.loadComponentFromURL(file_url, "_blank", 0, ())
        load_time = time.time() - start_time
        logger.info(f"Document loaded in {load_time:.2f}s")
        
        # Step 5: Execute macro
        logger.info("Step 5: Executing macro...")
        start_time = time.time()
        
        # Your macro execution code here
        script_provider = document.getScriptProvider()
        script = script_provider.getScript("vnd.sun.star.script:Standard.Module1.ProcessExcelFile?language=Basic&location=document")
        result = script.invoke((), (), ())
        
        exec_time = time.time() - start_time
        logger.info(f"Macro executed in {exec_time:.2f}s")
        logger.info(f"Macro result: {result}")
        
        # Step 6: Save and close
        logger.info("Step 6: Saving document...")
        document.storeToURL(uno.systemPathToFileUrl(os.path.abspath(output_path)), ())
        document.close(True)
        
        logger.info("✅ Excel processing completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error during processing: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False
    finally:
        # Cleanup
        if 'document' in locals():
            try:
                document.close(True)
            except:
                pass
        
        if process:
            process.terminate()
            logger.info("LibreOffice process terminated")

# Test function
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Test the process
    success = process_excel_with_detailed_logging("test.xlsx", "test_output.xlsx")
    logger.info(f"Final result: {'SUCCESS' if success else 'FAILED'}")