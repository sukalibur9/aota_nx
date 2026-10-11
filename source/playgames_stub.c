/* playgames_stub.c -- keep The Room Three's Google Play Games / CloudSave path
 * dormant, so the game runs entirely on local saves.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The Room Three's cloud save is driven by com.google.android.gms.tasks
 * CALLBACKS, not return values: the C# registers AndroidJavaProxy objects
 * implementing OnCompleteListener / OnSuccessListener / OnFailureListener and
 * then waits. Handing back a null sign-in client (which is what our JNI layer
 * does, since there are no Play Services here) means no listener ever fires --
 * so CloudSave.UpdateFinished() can stay false forever and a loading state can
 * hang. Returning a *live* client would be worse: it pushes the game into code
 * that genuinely cannot work.
 *
 * Fortunately the game gates the entire path behind two PlayerPrefs keys, both
 * confirmed as string literals in this build's global-metadata.dat:
 *
 *     UseGooglePlay   -- SocialPlatformManager.AutoSignInPref
 *                        read by ShouldAutoSignIn()
 *     CloudEnabled    -- CloudSave.CloudEnabledPref
 *                        read by IsCloudPlayerPrefEnabled()
 *
 * With both at 0, SocialPlatformManager.ShouldAutoSignIn() is false and
 * CloudSave.IsCloudAvailable() is false.
 *
 * IMPORTANT -- THIS IS NOT SUFFICIENT ON ITS OWN, and an earlier version of this
 * comment wrongly claimed it was. Seeding these keys stops the GAME asking for a
 * sign-in, but the Google Play Games plugin bootstraps ITSELF from
 * PlayGamesHelperObject.Update() and calls AndroidClient.Authenticate regardless
 * of any game pref. Observed on hardware: the prefs were both 0 and the plugin
 * still ran. The sign-in Task must therefore be completed properly in
 * jni_fake.c (see gpgs_complete_signin) -- that is what actually keeps the game
 * out of a soft-lock. These prefs remain useful for the game's own cloud UI. The
 * relevant managed surface -- every entry point a clean boolean gate with a
 * failure branch -- is:
 *
 *     SocialPlatformManager : MonoBehaviour
 *         ShouldAutoSignIn()   IsGooglePlayAvailable()   IsUserAuthenticated()
 *         GetIsSigningIn()     ProcessAuthentication(bool success)
 *     CloudSave
 *         IsCloudAvailable()   IsCloudPlayerPrefEnabled()
 *         GetCloudEnabled()    UpdateFinished()
 *
 * Fireproof wrote this to survive Play Services being absent, which is exactly
 * our situation. We only have to make sure it starts in that state.
 *
 * We seed the keys by writing prefs.kv directly BEFORE unity_jni.c loads it,
 * and only when the file does not already exist -- so a player who later turns
 * cloud on in-game (and gets it turned straight back off by the failing sign-in)
 * keeps whatever the game last wrote. Never clobber an existing save.
 *
 * prefs.kv format (see unity_jni.c): one record per line, "T\tkey\tval\n",
 * where T is S/I/L/F/B. Unity's PlayerPrefs has no bool, so both gates are
 * ints written through putInt -> 'I'.
 *
 * MIT.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "config.h"     /* GAME_HOME */

int debugPrintf(char *text, ...);

/* The two gates, and what we want them to start at. */
static const struct { const char *key; const char *val; const char *why; }
OS_PREF_SEED[] = {
  { "UseGooglePlay", "0", "SocialPlatformManager.ShouldAutoSignIn -> false" },
  { "CloudEnabled",  "0", "CloudSave.IsCloudPlayerPrefEnabled  -> false" },
};

/* Call once at boot, BEFORE the JNI layer's prefs_load() runs (which happens on
 * the first SharedPreferences access from the engine). main.c calls this right
 * after the game root is resolved. */
void r3_seed_playerprefs(void)
{
  char path[320];
  snprintf(path, sizeof path, "%s/prefs.kv", GAME_HOME);

  struct stat st;
  if (stat(path, &st) == 0) {
    debugPrintf("[r3] prefs.kv already exists (%lld bytes) -- not seeding\n",
                (long long)st.st_size);
    return;
  }

  FILE *f = fopen(path, "wb");
  if (!f) {
    debugPrintf("[r3] prefs.kv seed FAILED: fopen(%s) errno=%d\n", path, errno);
    return;
  }
  for (unsigned i = 0; i < sizeof OS_PREF_SEED / sizeof OS_PREF_SEED[0]; i++) {
    fprintf(f, "I\t%s\t%s\n", OS_PREF_SEED[i].key, OS_PREF_SEED[i].val);
    debugPrintf("[r3] seed pref %s=%s  (%s)\n",
                OS_PREF_SEED[i].key, OS_PREF_SEED[i].val, OS_PREF_SEED[i].why);
  }
  fclose(f);
  debugPrintf("[r3] prefs.kv seeded at %s\n", path);
}

/* ---------------------------------------------------------------------------
 * Diagnostic: if something DOES reach the Task machinery, we want it named in
 * the log rather than silently hanging. jni_fake.c's UNMATCHED logging already
 * covers the general case; this narrows it for the classes that specifically
 * lead to a stall, so the line is easy to spot.
 *
 * Returns 1 if the class is on the "this should never be reached" list.
 * ------------------------------------------------------------------------ */
int r3_is_stall_risk_class(const char *cls)
{
  static const char *const RISK[] = {
    "gms/tasks/Tasks",
    "OnCompleteListener",
    "OnSuccessListener",
    "OnFailureListener",
    "games/bridge/HelperFragment",
    "SnapshotMetadataChange",
  };
  if (!cls) return 0;
  for (unsigned i = 0; i < sizeof RISK / sizeof RISK[0]; i++)
    if (strstr(cls, RISK[i])) {
      debugPrintf("[r3] STALL RISK: %s reached -- the PlayerPrefs gates should "
                  "have prevented this. Check prefs.kv.\n", cls);
      return 1;
    }
  return 0;
}
