#include <stdio.h>
#include <string.h>

#define bool int
#define true 1
#define false 0

char* lineFromFile=NULL;
char* networkDevice=NULL;

bool GetDefaultGateway(char* DefaultGateway, char* GatewayDevice);
void HandleError(char* error);
void CleanUp();
unsigned char ToHex(char asciiHex);
unsigned char Combine(unsigned char firstByte,unsigned char secondByte);

bool  GetDefaultGateway(char* DefaultGateway, char* GatewayDevice)
{
	FILE* routeFile=NULL;
	char charFromFile=0;
	char gateWay[255];
	int lineCount=0;
	int i=0;
	int j=0;
	int wordCount=0;
	int gateWayCount=0;
	int gatewayInt[4];
	bool isFound=false;
	int totalLines=0;
	unsigned char convertedChar=0;

	routeFile = fopen("/proc/net/route","rb");

	if (routeFile == NULL)
	{
		HandleError("Can not open file!\n");
		return false;
	}

	lineFromFile = (char*)  malloc(255);

	while (1)
	{
		
		if (feof(routeFile) || isFound) break;
		
		charFromFile = fgetc(routeFile);	
		if (charFromFile == '\n')
		{
			
			lineFromFile[lineCount] = '\0';
			
			networkDevice = malloc(255);			

			i = 0;
			//Get Network Device
			for (i=0;i<lineCount;i++)
			{
				if (lineFromFile[i] > 0 && lineFromFile[i] < 33)
				{
					networkDevice[wordCount] = '\0';
					wordCount=0;
					break;
				} else {
					networkDevice[wordCount] = lineFromFile[i];
					wordCount++;
				}
			}
			
			if (strcmp(networkDevice, "Iface")  !=  0)
			{
				//skip the spaces, and tabs
				for (i=i; i < lineCount; i++)
				{
					if (lineFromFile[i] > 34)
					{
						break;
					}
				}


				//skip Destination
				for (i=i; i < lineCount;i++)
				{
					if (lineFromFile[i] > 0 && lineFromFile[i] < 33)
					{
						break;
					}
				}

				//skip the spaces, and tabs
				for (i=i; i < lineCount; i++)
				{
					if (lineFromFile[i] > 34)
					{
						break;
					}
				}

		
				//Get The Gateway
				gateWayCount=0;

				for (i=i;i< lineCount;i++)
				{
					if (lineFromFile[i] > 0 && lineFromFile[i] < 33)
					{
						gateWay[gateWayCount] = '\0';
						break;
					} else {
						gateWay[gateWayCount] = lineFromFile[i];
						gateWayCount++;
					}
				}
			

				for (i=0;i<gateWayCount;i++)
				{
					if (gateWay[0] != '0')
					{
						isFound = true;
						break;		
					}
				}
			}
			lineCount=0;
		} else {
			lineFromFile[lineCount] = charFromFile;
			lineCount++;
		}
	}
	fclose(routeFile);
	

	if (strlen(gateWay) > 1)
	{
		for (i=0;i<strlen(gateWay);i+=2)
		{
			convertedChar = Combine(ToHex(gateWay[i]),ToHex(gateWay[i+1]));
			gatewayInt[j] = 0;
			gatewayInt[j] |= convertedChar;
			j++;
		}
		sprintf(DefaultGateway,"%d.%d.%d.%d", gatewayInt[3], gatewayInt[2], gatewayInt[1], gatewayInt[0]);
	} else {
		DefaultGateway = NULL;
	}

	if (GatewayDevice != NULL)
	{
		strcpy(GatewayDevice,networkDevice);
	}

	CleanUp();
	
	return isFound;
}

void HandleError(char* error)
{
	printf("Error: %s", error);
	CleanUp();
}

unsigned char Combine(unsigned char firstByte,unsigned char secondByte)
{
	char returnByte = firstByte;
	returnByte <<= 4;
	returnByte |= secondByte;
	return returnByte;
}

unsigned char ToHex(char asciiHex)
{
	switch(asciiHex)
	{
		case '0':
			{
				return 0x00;
				break;
			}
		case '1':
			{
				return 0x01;
				break;
			}
		case '2':
			{
				return 0x02;
				break;
			}
		case '3':
			{
				return 0x03;
				break;
			}
		case '4':
			{
				return 0x04;
				break;
			}
		case '5':
			{
				return 0x05;
				break;
			}
		case '6':
			{
				return 0x06;
				break;
			}
		case '7':
			{
				return 0x07;
				break;
			}
		case '8':
			{
				return 0x08;
				break;
			}
		case '9':
			{
				return 0x09;
				break;
			}
		case 'A':
			{
				return 0x0A;
				break;
			}
		case 'B':
			{
				return 0x0B;
				break;
			}
		case 'C':
			{
				return 0x0C;
				break;
			}

		case 'D':
			{
				return 0x0D;
				break;
			}
		case 'E':
			{
				return 0x0E;
				break;
			}
		case 'F':
			{
				return 0x0F;
				break;
			}

	}
}


void CleanUp()
{
	if (lineFromFile != NULL)
	{
		free(lineFromFile);
		lineFromFile = NULL;
	}

	if (networkDevice != NULL)
	{
		free(networkDevice);
		networkDevice=NULL;
	}
}
