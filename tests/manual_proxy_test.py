import asyncssh
import asyncio
import sys

async def run_client():
    # Connect to the Proxy (port 2220)
    try:
        async with asyncssh.connect('127.0.0.1', port=2220, username='attacker', password='password', known_hosts=None) as conn:
            print("Connected to proxy.")
            # Run simple command
            result = await conn.run('whoami', check=True)
            print(f"Command output: {result.stdout.strip()}")
            
            # Interactive shell check
            async with conn.create_process() as process:
                process.stdin.write('ls -la\n')
                process.stdin.write('exit\n')
                await process.wait_closed()
                print(f"Interactive output: {await process.stdout.read()}")

    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(run_client())
    except (KeyboardInterrupt, SystemExit):
        pass
