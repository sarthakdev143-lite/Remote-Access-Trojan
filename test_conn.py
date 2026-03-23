import asyncio
import ssl

async def test():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.crt')
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        r, w = await asyncio.open_connection(
            'johnthehecker143-47209.portmap.host', 47209,
            ssl=ctx, server_hostname='localhost'
        )
        print('CONNECTED OK')
        w.close()
    except Exception as e:
        print(type(e).__name__, ':', e)

asyncio.run(test())