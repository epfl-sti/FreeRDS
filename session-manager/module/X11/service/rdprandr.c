/*
Copyright 2011-2012 Jay Sorg

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

RandR extension implementation

 */

#include "rdp.h"
#include "rdprandr.h"

#include <stdio.h>
#include <sys/shm.h>
#include <sys/stat.h>

#define LOG_LEVEL 0
#define LLOGLN(_level, _args) \
		do { if (_level < LOG_LEVEL) { ErrorF _args ; ErrorF("\n"); } } while (0)

extern rdpScreenInfoRec g_rdpScreen;
extern WindowPtr g_invalidate_window;

static XID g_wid = 0;

#define DEFINE_SCREEN_SIZE(_width, _height) ((_width << 16) | _height)

#define SCREEN_SIZE_WIDTH(_size) ((_size >> 16) & 0xFFFF)
#define SCREEN_SIZE_HEIGHT(_size) ((_size) & 0xFFFF)

#if 0
#define MAX_SCREEN_SIZE_WIDTH	0xFFFF
#define MAX_SCREEN_SIZE_HEIGHT	0xFFFF
#else
#define MAX_SCREEN_SIZE_WIDTH	1920
#define MAX_SCREEN_SIZE_HEIGHT	1080
#endif

static UINT32 g_StandardSizes[] =
{
	DEFINE_SCREEN_SIZE(8192, 4608),
	DEFINE_SCREEN_SIZE(4096, 2560),
	DEFINE_SCREEN_SIZE(4096, 2160),
	DEFINE_SCREEN_SIZE(3840, 2160),
	DEFINE_SCREEN_SIZE(2560, 1600), /* 16:10 */
	DEFINE_SCREEN_SIZE(2560, 1440),
	DEFINE_SCREEN_SIZE(2048, 1152),
	DEFINE_SCREEN_SIZE(2048, 1080),
	DEFINE_SCREEN_SIZE(1920, 1200), /* 16:10 */
	DEFINE_SCREEN_SIZE(1920, 1080),
	DEFINE_SCREEN_SIZE(1680, 1050), /* 16:10 */
	DEFINE_SCREEN_SIZE(1600, 1200),
	DEFINE_SCREEN_SIZE(1600, 900),
	DEFINE_SCREEN_SIZE(1440, 900), /* 16:10 */
	DEFINE_SCREEN_SIZE(1400, 1050),
	DEFINE_SCREEN_SIZE(1366, 768),
	DEFINE_SCREEN_SIZE(1280, 1024),
	DEFINE_SCREEN_SIZE(1280, 960),
	DEFINE_SCREEN_SIZE(1280, 800), /* 16:10 */
	DEFINE_SCREEN_SIZE(1280, 720),
	DEFINE_SCREEN_SIZE(1152, 864),
	DEFINE_SCREEN_SIZE(1024, 768),
	DEFINE_SCREEN_SIZE(800, 600),
	DEFINE_SCREEN_SIZE(640, 480)
};

static int get_max_shared_memory_segment_size(void)
{
#ifdef _GNU_SOURCE
	struct shminfo info;

	if ((shmctl(0, IPC_INFO, (struct shmid_ds*)(void*)&info)) == -1)
		return -1;

	return info.shmmax;
#else
	return -1;
#endif
}

Bool rdpRRRegisterSize(ScreenPtr pScreen, int width, int height)
{
	int k;
	int index;
	int cIndex;
	int shmmax;
	int cWidth, cHeight;
	int mmWidth, mmHeight;
	RRScreenSizePtr pSizes[32];

	LLOGLN(0, ("rdpRRRegisterSize width: %d height: %d", width, height));

	index = 0;
	cIndex = -1;
	cWidth = width;
	cHeight = height;

	shmmax = get_max_shared_memory_segment_size();

	for (k = 0; k < sizeof(g_StandardSizes) / sizeof(UINT32); k++)
	{
		width = SCREEN_SIZE_WIDTH(g_StandardSizes[k]);
		height = SCREEN_SIZE_HEIGHT(g_StandardSizes[k]);

		if ((width > MAX_SCREEN_SIZE_WIDTH) || (height > MAX_SCREEN_SIZE_HEIGHT))
			continue; /* screen size is too large */

		if (shmmax > 0)
		{
			if ((width * height * 4) > shmmax)
				continue; /* required buffer size is too large */
		}

		mmWidth = PixelToMM(width);
		mmHeight = PixelToMM(height);

		if ((width == cWidth) && (height == cHeight))
			cIndex = index;

		pSizes[index] = RRRegisterSize(pScreen, width, height, mmWidth, mmHeight);
		RRRegisterRate(pScreen, pSizes[index], 60);

		index++;
	}

	width = cWidth;
	height = cHeight;

	if (cIndex < 0)
	{
		cIndex = index;

		mmWidth = PixelToMM(width);
		mmHeight = PixelToMM(height);

		pSizes[index] = RRRegisterSize(pScreen, width, height, mmWidth, mmHeight);
		RRRegisterRate(pScreen, pSizes[index], 60);
	}

	RRSetCurrentConfig(pScreen, RR_Rotate_0, 60, pSizes[cIndex]);

	return TRUE;
}

Bool rdpRRSetConfig(ScreenPtr pScreen, Rotation rotateKind, int rate, RRScreenSizePtr pSize)
{
	LLOGLN(0, ("rdpRRSetConfig: rate: %d id: %d width: %d height: %d mmWidth: %d mmHeight: %d",
			rate, pSize->id, pSize->width, pSize->height, pSize->mmWidth, pSize->mmHeight));

	return TRUE;
}

Bool rdpRRGetInfo(ScreenPtr pScreen, Rotation* pRotations)
{
	LLOGLN(0, ("rdpRRGetInfo"));

	if (pRotations)
		*pRotations = RR_Rotate_0;

	rdpRRRegisterSize(pScreen, pScreen->width, pScreen->height);

	return TRUE;
}

Bool rdpRRSetInfo(ScreenPtr pScreen)
{
	return TRUE;
}

/**
 * for lack of a better way, a window is created that covers
 * the area and when its deleted, it's invalidated
 */
static int rdpInvalidateArea(ScreenPtr pScreen, int x, int y, int width, int height)
{
	int attri;
	Mask mask;
	int result;
	WindowPtr pWin;
	XID attributes[4];

	mask = 0;
	attri = 0;
	attributes[attri++] = pScreen->blackPixel;
	mask |= CWBackPixel;
	attributes[attri++] = xTrue;
	mask |= CWOverrideRedirect;

	if (g_wid == 0)
	{
		g_wid = FakeClientID(0);
	}

	pWin = CreateWindow(g_wid, pScreen->root,
			x, y, width, height, 0, InputOutput, mask,
			attributes, 0, serverClient,
			wVisual(pScreen->root), &result);

	if (result == 0)
	{
		g_invalidate_window = pWin;
		MapWindow(pWin, serverClient);
		DeleteWindow(pWin, None);
		g_invalidate_window = pWin;
	}

	return 0;
}

Bool rdpRRScreenSetSize(ScreenPtr pScreen, CARD16 width, CARD16 height, CARD32 mmWidth, CARD32 mmHeight)
{
	BoxRec box;
	PixmapPtr screenPixmap;

	LLOGLN(0, ("rdpRRScreenSetSize: width: %d height: %d mmWidth: %d mmHeight: %d",
			width, height, mmWidth, mmHeight));

	if ((width < 1) || (height < 1))
	{
		return FALSE;
	}

	rdpup_detach_framebuffer();

	g_rdpScreen.width = width;
	g_rdpScreen.height = height;
	g_rdpScreen.paddedWidthInBytes = PixmapBytePad(g_rdpScreen.width, g_rdpScreen.depth);
	g_rdpScreen.sizeInBytes = g_rdpScreen.paddedWidthInBytes * g_rdpScreen.height;

	pScreen->x = 0;
	pScreen->y = 0;
	pScreen->width = width;
	pScreen->height = height;
	pScreen->mmWidth = mmWidth;
	pScreen->mmHeight = mmHeight;

	screenInfo.x = 0;
	screenInfo.y = 0;
	screenInfo.width = width;
	screenInfo.height = height;

	if (g_rdpScreen.pfbMemory)
	{
		if (g_rdpScreen.sharedMemory)
		{
			/* detach shared memory segment */
			shmdt(g_rdpScreen.pfbMemory);
			g_rdpScreen.pfbMemory = NULL;

			/* deallocate shared memory segment */
			shmctl(g_rdpScreen.segmentId, IPC_RMID, 0);

			/* allocate shared memory segment */
			g_rdpScreen.segmentId = shmget(IPC_PRIVATE, g_rdpScreen.sizeInBytes,
					IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

			/* attach the shared memory segment */
			g_rdpScreen.pfbMemory = (char*) shmat(g_rdpScreen.segmentId, 0, 0);
		}
		else
		{
			g_rdpScreen.pfbMemory = (char*) malloc(g_rdpScreen.sizeInBytes);
		}

		if (!g_rdpScreen.pfbMemory)
		{
			rdpLog("rdpScreenInit pfbMemory malloc failed\n");
			return 0;
		}

		ZeroMemory(g_rdpScreen.pfbMemory, g_rdpScreen.sizeInBytes);
	}

	screenPixmap = pScreen->GetScreenPixmap(pScreen);

	if (screenPixmap)
	{
		pScreen->ModifyPixmapHeader(screenPixmap, width, height,
				g_rdpScreen.depth, g_rdpScreen.bitsPerPixel,
				g_rdpScreen.paddedWidthInBytes,
				g_rdpScreen.pfbMemory);
	}

	box.x1 = 0;
	box.y1 = 0;
	box.x2 = width;
	box.y2 = height;

	RegionInit(&pScreen->root->winSize, &box, 1);
	RegionInit(&pScreen->root->borderSize, &box, 1);
	RegionReset(&pScreen->root->borderClip, &box);
	RegionBreak(&pScreen->root->clipList);

	pScreen->root->drawable.width = width;
	pScreen->root->drawable.height = height;

	ResizeChildrenWinSize(pScreen->root, 0, 0, 0, 0);

	RRGetInfo(pScreen, 1);

	rdpInvalidateArea(pScreen, 0, 0, pScreen->width, pScreen->height);

	RRScreenSizeNotify(pScreen);
	RRTellChanged(pScreen);

	return TRUE;
}

Bool rdpRRCrtcSet(ScreenPtr pScreen, RRCrtcPtr crtc, RRModePtr mode,
		int x, int y, Rotation rotation, int numOutputs, RROutputPtr* outputs)
{
	LLOGLN(0, ("rdpRRCrtcSet: x: %d y: %d numOutputs: %d",
			x, y, numOutputs));

	return RRCrtcNotify(crtc, mode, x, y, rotation, NULL, numOutputs, outputs);
}

Bool rdpRRCrtcSetGamma(ScreenPtr pScreen, RRCrtcPtr crtc)
{
	LLOGLN(0, ("rdpRRCrtcSetGamma"));

	return TRUE;
}

Bool rdpRRCrtcGetGamma(ScreenPtr pScreen, RRCrtcPtr crtc)
{
	LLOGLN(0, ("rdpRRCrtcGetGamma"));

	return TRUE;
}

Bool rdpRROutputSetProperty(ScreenPtr pScreen, RROutputPtr output, Atom property, RRPropertyValuePtr value)
{
	LLOGLN(0, ("rdpRROutputSetProperty"));

	return TRUE;
}

Bool rdpRROutputValidateMode(ScreenPtr pScreen, RROutputPtr output, RRModePtr mode)
{
	LLOGLN(0, ("rdpRROutputValidateMode"));

	return TRUE;
}

void rdpRRModeDestroy(ScreenPtr pScreen, RRModePtr mode)
{
	LLOGLN(0, ("rdpRRModeDestroy"));
}

Bool rdpRROutputGetProperty(ScreenPtr pScreen, RROutputPtr output, Atom property)
{
	const char* name;

	name = NameForAtom(property);

	LLOGLN(0, ("rdpRROutputGetProperty: Atom: %s", name));

	if (!name)
		return FALSE;

	if (strcmp(name, "EDID"))
	{

	}

	return TRUE;
}

Bool rdpRRGetPanning(ScreenPtr pScreen, RRCrtcPtr crtc, BoxPtr totalArea, BoxPtr trackingArea, INT16* border)
{
	LLOGLN(100, ("rdpRRGetPanning"));

	if (crtc)
	{
		LLOGLN(100, ("rdpRRGetPanning: ctrc->id: %d", crtc->id));
	}

	if (totalArea)
	{
		totalArea->x1 = 0;
		totalArea->y1 = 0;
		totalArea->x2 = pScreen->width;
		totalArea->y2 = pScreen->height;

		LLOGLN(100, ("rdpRRGetPanning: totalArea: x1: %d y1: %d x2: %d y2: %d",
				totalArea->x1, totalArea->y1, totalArea->x1, totalArea->y2));
	}

	if (trackingArea)
	{
		trackingArea->x1 = 0;
		trackingArea->y1 = 0;
		trackingArea->x2 = pScreen->width;
		trackingArea->y2 = pScreen->height;

		LLOGLN(100, ("rdpRRGetPanning: trackingArea: x1: %d y1: %d x2: %d y2: %d",
				trackingArea->x1, trackingArea->y1, trackingArea->x1, trackingArea->y2));
	}

	if (border)
	{
		border[0] = 0;
		border[1] = 0;
		border[2] = 0;
		border[3] = 0;
	}

	return TRUE;
}

Bool rdpRRSetPanning(ScreenPtr pScrn, RRCrtcPtr crtc, BoxPtr totalArea, BoxPtr trackingArea, INT16* border)
{
	LLOGLN(0, ("rdpRRSetPanning"));

	return TRUE;
}

#if (RANDR_INTERFACE_VERSION >= 0x0104)

Bool rdpRRCrtcSetScanoutPixmap(RRCrtcPtr crtc, PixmapPtr pixmap)
{
	LLOGLN(0, ("rdpRRCrtcSetScanoutPixmap"));

	return TRUE;
}

Bool rdpRRProviderSetOutputSource(ScreenPtr pScreen, RRProviderPtr provider, RRProviderPtr output_source)
{
	LLOGLN(0, ("rdpRRProviderSetOutputSource"));

	return TRUE;
}

Bool rdpRRProviderSetOffloadSink(ScreenPtr pScreen, RRProviderPtr provider, RRProviderPtr offload_sink)
{
	LLOGLN(0, ("rdpRRProviderSetOffloadSink"));

	return TRUE;
}

Bool rdpRRProviderGetProperty(ScreenPtr pScreen, RRProviderPtr provider, Atom property)
{
	LLOGLN(0, ("rdpRRProviderGetProperty"));

	return TRUE;
}

Bool rdpRRProviderSetProperty(ScreenPtr pScreen, RRProviderPtr provider, Atom property, RRPropertyValuePtr value)
{
	LLOGLN(0, ("rdpRRProviderGetProperty"));

	return TRUE;
}

void rdpRRProviderDestroy(ScreenPtr pScreen, RRProviderPtr provider)
{
	LLOGLN(0, ("rdpRRProviderDestroy"));
}

#endif

int rdpRRInit(ScreenPtr pScreen)
{
#if RANDR_12_INTERFACE
	char name[64];
	RRModePtr mode;
	RRCrtcPtr crtc;
	RROutputPtr output;
	xRRModeInfo modeInfo;
#if (RANDR_INTERFACE_VERSION >= 0x0104)
	RRProviderPtr provider;
	uint32_t capabilities;
#endif
#endif
	rrScrPrivPtr pScrPriv;

	LLOGLN(0, ("rdpRRInit"));

	if (!RRScreenInit(pScreen))
		return -1;

	pScrPriv = rrGetScrPriv(pScreen);

	pScrPriv->rrSetConfig = rdpRRSetConfig;

	pScrPriv->rrGetInfo = rdpRRGetInfo;

	pScrPriv->rrScreenSetSize = rdpRRScreenSetSize;

#if RANDR_12_INTERFACE
	pScrPriv->rrCrtcSet = rdpRRCrtcSet;
	pScrPriv->rrCrtcSetGamma = rdpRRCrtcSetGamma;
	pScrPriv->rrCrtcGetGamma = rdpRRCrtcGetGamma;
	pScrPriv->rrOutputSetProperty = rdpRROutputSetProperty;
	pScrPriv->rrOutputValidateMode = rdpRROutputValidateMode;
	pScrPriv->rrModeDestroy = rdpRRModeDestroy;

#if RANDR_13_INTERFACE
	pScrPriv->rrOutputGetProperty = rdpRROutputGetProperty;
	pScrPriv->rrGetPanning = rdpRRGetPanning;
	pScrPriv->rrSetPanning = rdpRRSetPanning;
#endif

#if (RANDR_INTERFACE_VERSION >= 0x0104)
	pScrPriv->rrCrtcSetScanoutPixmap = rdpRRCrtcSetScanoutPixmap;
	pScrPriv->rrProviderSetOutputSource = rdpRRProviderSetOutputSource;
	pScrPriv->rrProviderSetOffloadSink = rdpRRProviderSetOffloadSink;
	pScrPriv->rrProviderGetProperty = rdpRRProviderGetProperty;
	pScrPriv->rrProviderSetProperty = rdpRRProviderSetProperty;
	pScrPriv->rrProviderDestroy = rdpRRProviderDestroy;
#endif

	RRScreenSetSizeRange(pScreen, 8, 8, 16384, 16384);

	/**
	 * Refer to the VESA Generalized Timing Formula (GTF): GTF_V1R1.xls
	 *
	 * Modeline "String description" Dot-Clock HDisp HSyncStart HSyncEnd HTotal VDisp VSyncStart VSyncEnd VTotal [options]
	 *
	 * # 1024x768 @ 60.00 Hz (GTF) hsync: 47.70 kHz; pclk: 64.11 MHz
	 * Modeline "1024x768_60.00"  64.11  1024 1080 1184 1344  768 769 772 795  -HSync +Vsync
	 *
	 * When most of the modeline information is set to zero, xorg-server appears to be populating it with default values
	 *
	 */

	sprintf(name, "%dx%d", pScreen->width, pScreen->height);
	ZeroMemory(&modeInfo, sizeof(xRRModeInfo));

	modeInfo.id = 0;

	modeInfo.width = pScreen->width;
	modeInfo.hSyncStart = 0;
	modeInfo.hSyncEnd = 0;
	modeInfo.hTotal = 0;

	modeInfo.height = pScreen->height;
	modeInfo.vSyncStart = 0;
	modeInfo.vSyncEnd = 0;
	modeInfo.vTotal = 0;

	/* DotClock = RefreshRate * HTotal * VTotal */
	modeInfo.dotClock = 60 * modeInfo.hTotal * modeInfo.vTotal;

	modeInfo.hSkew = 0;
	modeInfo.nameLength = strlen(name);

	/**
	 * Sample EDID:
	 *
	 * 00ffffffffffff001e6d8d5736210100
	 * 0a140103e0301b78ea3337a5554d9d25
	 * 115052a54b00b3008180818f714f0101
	 * 010101010101023a801871382d40582c
	 * 4500dd0c1100001a000000fd00384b1e
	 * 530f000a202020202020000000fc0045
	 * 323235300a20202020202020000000ff
	 * 003031304e44524632363033380a00a2
	 */

	mode = RRModeGet(&modeInfo, name);

	if (!mode)
		return -1;

	crtc = RRCrtcCreate(pScreen, NULL);

	if (!crtc)
		return FALSE;

	RRCrtcGammaSetSize(crtc, 256);

	output = RROutputCreate(pScreen, "RDP-0", strlen("RDP-0"), NULL);

	if (!output)
		return -1;

	if (!RROutputSetClones(output, NULL, 0))
		return -1;

	if (!RROutputSetModes(output, &mode, 1, 0))
		return -1;

	if (!RROutputSetCrtcs(output, &crtc, 1))
		return -1;

	if (!RROutputSetSubpixelOrder(output, SubPixelUnknown))
		return -1;

	if (!RROutputSetPhysicalSize(output, 521, 293))
		return -1;

	if (!RROutputSetConnection(output, RR_Connected))
		return -1;

#if (RANDR_INTERFACE_VERSION >= 0x0104)
	provider = RRProviderCreate(pScreen, "RDP", strlen("RDP"));

	capabilities = RR_Capability_None;
	capabilities |= RR_Capability_SourceOutput;
	capabilities |= RR_Capability_SinkOutput;
	capabilities |= RR_Capability_SourceOffload;
	capabilities |= RR_Capability_SinkOffload;

	RRProviderSetCapabilities(provider, capabilities);
#endif

	RRCrtcNotify(crtc, mode, 0, 0, RR_Rotate_0, NULL, 1, &output);
#endif

	return 0;
}
