#ifndef _ZT_VERSION_H
#define _ZT_VERSION_H

/**
 * Major version
 */
#define ZEROTIER_ONE_VERSION_MAJOR 1

/**
 * Minor version
 */
#define ZEROTIER_ONE_VERSION_MINOR 2

/**
 * Revision
 */
#define ZEROTIER_ONE_VERSION_REVISION 5

/**
 * Build version
 *
 * This starts at 0 for each major.minor.rev tuple and can be incremented
 * to force a minor update without an actual version number change. It's
 * not part of the actual release version number.
 */
#define ZEROTIER_ONE_VERSION_BUILD 0

#ifndef ZT_BUILD_ARCHITECTURE
#define ZT_BUILD_ARCHITECTURE 0
#endif
#ifndef ZT_BUILD_PLATFORM
#define ZT_BUILD_PLATFORM 0
#endif

#endif


