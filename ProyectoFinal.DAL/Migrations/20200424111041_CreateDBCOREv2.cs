using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ProyectoFinal.DAL.Migrations
{
    public partial class CreateDBCOREv2 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Malwares",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    User_Id = table.Column<string>(nullable: true),
                    UserId = table.Column<string>(nullable: true),
                    Date = table.Column<DateTime>(nullable: false),
                    MD5 = table.Column<string>(nullable: true),
                    SHA256 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Tags = table.Column<string>(nullable: true),
                    MalwareStatus = table.Column<int>(nullable: false),
                    MalwareLevel = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Malwares", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Malwares_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Comments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    User_Id = table.Column<string>(nullable: true),
                    UserId = table.Column<string>(nullable: true),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    TextComment = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Comments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Comments_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Comments_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooInfos",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Category = table.Column<string>(nullable: true),
                    Package = table.Column<string>(nullable: true),
                    Score = table.Column<float>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooInfos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooInfos_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooSignatures",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Description = table.Column<string>(nullable: true),
                    Markcount = table.Column<int>(nullable: false),
                    Severity = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooSignatures", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooSignatures_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Files",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    PathFile = table.Column<string>(nullable: true),
                    Type = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Files", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Files_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ScreenShots",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    PathFile = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScreenShots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScreenShots_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ThreatCrowdInfo",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    Votes = table.Column<int>(nullable: false),
                    Permalink = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatCrowdInfo", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ThreatCrowdInfo_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalInfo",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    MalwareId = table.Column<int>(nullable: true),
                    Total = table.Column<int>(nullable: false),
                    Positives = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalInfo", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalInfo_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooBehaviors",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Cuckoo_Id = table.Column<int>(nullable: false),
                    CuckooInfoId = table.Column<int>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooBehaviors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooBehaviors_CuckooInfos_CuckooInfoId",
                        column: x => x.CuckooInfoId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooDroppeds",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Cuckoo_Id = table.Column<int>(nullable: false),
                    CuckoInfoId = table.Column<int>(nullable: true),
                    crc32 = table.Column<string>(nullable: true),
                    FilePath = table.Column<string>(nullable: true),
                    md5 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Path = table.Column<string>(nullable: true),
                    Size = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooDroppeds", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooDroppeds_CuckooInfos_CuckoInfoId",
                        column: x => x.CuckoInfoId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooStatics",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Cuckoo_Id = table.Column<int>(nullable: false),
                    CuckooInfoId = table.Column<int>(nullable: true),
                    ImportedDllCount = table.Column<int>(nullable: false),
                    PeImphash = table.Column<string>(nullable: true),
                    PeTimestamp = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooStatics", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooStatics_CuckooInfos_CuckooInfoId",
                        column: x => x.CuckooInfoId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooTargets",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Cuckoo_Id = table.Column<int>(nullable: false),
                    CuckooInfoId = table.Column<int>(nullable: true),
                    crc32 = table.Column<string>(nullable: true),
                    FilePath = table.Column<string>(nullable: true),
                    md5 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Path = table.Column<string>(nullable: true),
                    Size = table.Column<int>(nullable: false),
                    Ssdeep = table.Column<string>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    YaraName = table.Column<string>(nullable: true),
                    YaraDescription = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooTargets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooTargets_CuckooInfos_CuckooInfoId",
                        column: x => x.CuckooInfoId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Marks",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Siganture_Id = table.Column<int>(nullable: false),
                    CuckooSignatureId = table.Column<int>(nullable: true),
                    Cid = table.Column<int>(nullable: true),
                    Pid = table.Column<int>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    Category = table.Column<string>(nullable: true),
                    Description = table.Column<string>(nullable: true),
                    Ioc = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Marks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Marks_CuckooSignatures_CuckooSignatureId",
                        column: x => x.CuckooSignatureId,
                        principalTable: "CuckooSignatures",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "SignatureReferences",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooSignature_Id = table.Column<int>(nullable: false),
                    CuckooSignatureId = table.Column<int>(nullable: true),
                    References = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignatureReferences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SignatureReferences_CuckooSignatures_CuckooSignatureId",
                        column: x => x.CuckooSignatureId,
                        principalTable: "CuckooSignatures",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCDomains",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Domain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCDomains", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCDomains_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCEmails",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Email = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCEmails", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCEmails_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCHashes",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Hash = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCHashes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCHashes_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCIps",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Ip = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCIps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCIps_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCReferences",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Reference = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCReferences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCReferences_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCResolutions",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    LastResolved = table.Column<string>(nullable: true),
                    Ip = table.Column<string>(nullable: true),
                    Domain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCResolutions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCResolutions_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCScans",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Scan = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCScans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCScans_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCSubdomanins",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Subdomain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCSubdomanins", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCSubdomanins_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalComments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VirusTotal_Id = table.Column<int>(nullable: false),
                    VirusTotalId = table.Column<int>(nullable: true),
                    Date = table.Column<DateTime>(nullable: false),
                    Comment = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalComments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalComments_VirusTotalInfo_VirusTotalId",
                        column: x => x.VirusTotalId,
                        principalTable: "VirusTotalInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalScans",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VirusTotal_Id = table.Column<int>(nullable: false),
                    VirusTotalId = table.Column<int>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Detected = table.Column<bool>(nullable: false),
                    Result = table.Column<string>(nullable: true),
                    Version = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalScans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalScans_VirusTotalInfo_VirusTotalId",
                        column: x => x.VirusTotalId,
                        principalTable: "VirusTotalInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "BehaviorSummaries",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Behavior_Id = table.Column<int>(nullable: false),
                    CuckooBehaviorId = table.Column<int>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Strings = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BehaviorSummaries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BehaviorSummaries_CuckooBehaviors_CuckooBehaviorId",
                        column: x => x.CuckooBehaviorId,
                        principalTable: "CuckooBehaviors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ProcessTrees",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Behavior_Id = table.Column<int>(nullable: false),
                    CuckooBehaviorId = table.Column<int>(nullable: true),
                    CommandLine = table.Column<string>(nullable: true),
                    FirstSeen = table.Column<double>(nullable: false),
                    Pid = table.Column<long>(nullable: false),
                    Ppid = table.Column<long>(nullable: false),
                    ProcessName = table.Column<string>(nullable: true),
                    Track = table.Column<bool>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessTrees", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ProcessTrees_CuckooBehaviors_CuckooBehaviorId",
                        column: x => x.CuckooBehaviorId,
                        principalTable: "CuckooBehaviors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DroppedPids",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Dropped_Id = table.Column<int>(nullable: false),
                    CuckooDroppedId = table.Column<int>(nullable: true),
                    Pid = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DroppedPids", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DroppedPids_CuckooDroppeds_CuckooDroppedId",
                        column: x => x.CuckooDroppedId,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DroppedUrls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Dropped_Id = table.Column<int>(nullable: false),
                    CuckooDroppedId = table.Column<int>(nullable: true),
                    Url = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DroppedUrls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DroppedUrls_CuckooDroppeds_CuckooDroppedId",
                        column: x => x.CuckooDroppedId,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "YaraDroppeds",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Dropped_Id = table.Column<int>(nullable: false),
                    CuckooDroppedId = table.Column<int>(nullable: true),
                    crc32 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Description = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_YaraDroppeds", x => x.Id);
                    table.ForeignKey(
                        name: "FK_YaraDroppeds_CuckooDroppeds_CuckooDroppedId",
                        column: x => x.CuckooDroppedId,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PeExports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    Dll = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeExports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeExports_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PeImports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    Dll = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeImports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeImports_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PeResources",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    Filetype = table.Column<string>(nullable: true),
                    Language = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Offset = table.Column<string>(nullable: true),
                    Size = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeResources", x => x.id);
                    table.ForeignKey(
                        name: "FK_PeResources_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PeSections",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    Entropy = table.Column<double>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    SizeOfData = table.Column<string>(nullable: true),
                    VirtualAddress = table.Column<string>(nullable: true),
                    VirtualSize = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeSections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeSections_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "StaticKeys",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    Keys = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StaticKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StaticKeys_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "StaticSignatures",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    CuckooStaticId = table.Column<int>(nullable: true),
                    CommonName = table.Column<string>(nullable: true),
                    Country = table.Column<string>(nullable: true),
                    Email = table.Column<string>(nullable: true),
                    Locality = table.Column<string>(nullable: true),
                    Organization = table.Column<string>(nullable: true),
                    SerialNumber = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StaticSignatures", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StaticSignatures_CuckooStatics_CuckooStaticId",
                        column: x => x.CuckooStaticId,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TargetPids",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Target_Id = table.Column<int>(nullable: false),
                    CuckooTargetId = table.Column<int>(nullable: true),
                    Pid = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetPids", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetPids_CuckooTargets_CuckooTargetId",
                        column: x => x.CuckooTargetId,
                        principalTable: "CuckooTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TargetUrls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Target_Id = table.Column<int>(nullable: false),
                    CuckooTargetId = table.Column<int>(nullable: true),
                    Url = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetUrls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetUrls_CuckooTargets_CuckooTargetId",
                        column: x => x.CuckooTargetId,
                        principalTable: "CuckooTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "MarkCalls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Mark_Id = table.Column<int>(nullable: false),
                    MarkId = table.Column<int>(nullable: true),
                    Api = table.Column<string>(nullable: true),
                    Category = table.Column<string>(nullable: true),
                    Status = table.Column<long>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkCalls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkCalls_Marks_MarkId",
                        column: x => x.MarkId,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "MarkSections",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Mark_Id = table.Column<int>(nullable: false),
                    MarkId = table.Column<int>(nullable: true),
                    Entropy = table.Column<long>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    SizeOfData = table.Column<string>(nullable: true),
                    VirtualAddress = table.Column<string>(nullable: true),
                    VirtualSize = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkSections", x => x.id);
                    table.ForeignKey(
                        name: "FK_MarkSections_Marks_MarkId",
                        column: x => x.MarkId,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Exports",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PeExport_Id = table.Column<int>(nullable: false),
                    PeExportId = table.Column<int>(nullable: true),
                    Address = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Exports", x => x.id);
                    table.ForeignKey(
                        name: "FK_Exports_PeExports_PeExportId",
                        column: x => x.PeExportId,
                        principalTable: "PeExports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Imports",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PeImport_Id = table.Column<int>(nullable: false),
                    PeImportId = table.Column<int>(nullable: true),
                    Address = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Imports", x => x.id);
                    table.ForeignKey(
                        name: "FK_Imports_PeImports_PeImportId",
                        column: x => x.PeImportId,
                        principalTable: "PeImports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "MarkArguments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MarkCall_Id = table.Column<int>(nullable: false),
                    MarkCallId = table.Column<int>(nullable: true),
                    BaseAddress = table.Column<string>(nullable: true),
                    Length = table.Column<long>(nullable: true),
                    ProcessHandle = table.Column<string>(nullable: true),
                    ProcessIdentifier = table.Column<int>(nullable: true),
                    Protection = table.Column<int>(nullable: true),
                    AllocationType = table.Column<long>(nullable: true),
                    RegionSize = table.Column<long>(nullable: true),
                    FreeBytes = table.Column<long>(nullable: true),
                    RootPath = table.Column<string>(nullable: true),
                    TotalNumberOfBytes = table.Column<double>(nullable: true),
                    TotalNumberOfFreeBytes = table.Column<long>(nullable: true),
                    Access = table.Column<string>(nullable: true),
                    BaseHandle = table.Column<string>(nullable: true),
                    KeyHandle = table.Column<string>(nullable: true),
                    Options = table.Column<long>(nullable: true),
                    Regkey = table.Column<string>(nullable: true),
                    RegkeyR = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkArguments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkArguments_MarkCalls_MarkCallId",
                        column: x => x.MarkCallId,
                        principalTable: "MarkCalls",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BehaviorSummaries_CuckooBehaviorId",
                table: "BehaviorSummaries",
                column: "CuckooBehaviorId");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_MalwareId",
                table: "Comments",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_UserId",
                table: "Comments",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooBehaviors_CuckooInfoId",
                table: "CuckooBehaviors",
                column: "CuckooInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooDroppeds_CuckoInfoId",
                table: "CuckooDroppeds",
                column: "CuckoInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooInfos_MalwareId",
                table: "CuckooInfos",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooSignatures_MalwareId",
                table: "CuckooSignatures",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooStatics_CuckooInfoId",
                table: "CuckooStatics",
                column: "CuckooInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooTargets_CuckooInfoId",
                table: "CuckooTargets",
                column: "CuckooInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_DroppedPids_CuckooDroppedId",
                table: "DroppedPids",
                column: "CuckooDroppedId");

            migrationBuilder.CreateIndex(
                name: "IX_DroppedUrls_CuckooDroppedId",
                table: "DroppedUrls",
                column: "CuckooDroppedId");

            migrationBuilder.CreateIndex(
                name: "IX_Exports_PeExportId",
                table: "Exports",
                column: "PeExportId");

            migrationBuilder.CreateIndex(
                name: "IX_Files_MalwareId",
                table: "Files",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_Imports_PeImportId",
                table: "Imports",
                column: "PeImportId");

            migrationBuilder.CreateIndex(
                name: "IX_Malwares_UserId",
                table: "Malwares",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MarkArguments_MarkCallId",
                table: "MarkArguments",
                column: "MarkCallId");

            migrationBuilder.CreateIndex(
                name: "IX_MarkCalls_MarkId",
                table: "MarkCalls",
                column: "MarkId");

            migrationBuilder.CreateIndex(
                name: "IX_Marks_CuckooSignatureId",
                table: "Marks",
                column: "CuckooSignatureId");

            migrationBuilder.CreateIndex(
                name: "IX_MarkSections_MarkId",
                table: "MarkSections",
                column: "MarkId");

            migrationBuilder.CreateIndex(
                name: "IX_PeExports_CuckooStaticId",
                table: "PeExports",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_PeImports_CuckooStaticId",
                table: "PeImports",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_PeResources_CuckooStaticId",
                table: "PeResources",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_PeSections_CuckooStaticId",
                table: "PeSections",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessTrees_CuckooBehaviorId",
                table: "ProcessTrees",
                column: "CuckooBehaviorId");

            migrationBuilder.CreateIndex(
                name: "IX_ScreenShots_MalwareId",
                table: "ScreenShots",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_SignatureReferences_CuckooSignatureId",
                table: "SignatureReferences",
                column: "CuckooSignatureId");

            migrationBuilder.CreateIndex(
                name: "IX_StaticKeys_CuckooStaticId",
                table: "StaticKeys",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_StaticSignatures_CuckooStaticId",
                table: "StaticSignatures",
                column: "CuckooStaticId");

            migrationBuilder.CreateIndex(
                name: "IX_TargetPids_CuckooTargetId",
                table: "TargetPids",
                column: "CuckooTargetId");

            migrationBuilder.CreateIndex(
                name: "IX_TargetUrls_CuckooTargetId",
                table: "TargetUrls",
                column: "CuckooTargetId");

            migrationBuilder.CreateIndex(
                name: "IX_TCDomains_ThreatCrowdInfoId",
                table: "TCDomains",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCEmails_ThreatCrowdInfoId",
                table: "TCEmails",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCHashes_ThreatCrowdInfoId",
                table: "TCHashes",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCIps_ThreatCrowdInfoId",
                table: "TCIps",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCReferences_ThreatCrowdInfoId",
                table: "TCReferences",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCResolutions_ThreatCrowdInfoId",
                table: "TCResolutions",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCScans_ThreatCrowdInfoId",
                table: "TCScans",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCSubdomanins_ThreatCrowdInfoId",
                table: "TCSubdomanins",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatCrowdInfo_MalwareId",
                table: "ThreatCrowdInfo",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalComments_VirusTotalId",
                table: "VirusTotalComments",
                column: "VirusTotalId");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalInfo_MalwareId",
                table: "VirusTotalInfo",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalScans_VirusTotalId",
                table: "VirusTotalScans",
                column: "VirusTotalId");

            migrationBuilder.CreateIndex(
                name: "IX_YaraDroppeds_CuckooDroppedId",
                table: "YaraDroppeds",
                column: "CuckooDroppedId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BehaviorSummaries");

            migrationBuilder.DropTable(
                name: "Comments");

            migrationBuilder.DropTable(
                name: "DroppedPids");

            migrationBuilder.DropTable(
                name: "DroppedUrls");

            migrationBuilder.DropTable(
                name: "Exports");

            migrationBuilder.DropTable(
                name: "Files");

            migrationBuilder.DropTable(
                name: "Imports");

            migrationBuilder.DropTable(
                name: "MarkArguments");

            migrationBuilder.DropTable(
                name: "MarkSections");

            migrationBuilder.DropTable(
                name: "PeResources");

            migrationBuilder.DropTable(
                name: "PeSections");

            migrationBuilder.DropTable(
                name: "ProcessTrees");

            migrationBuilder.DropTable(
                name: "ScreenShots");

            migrationBuilder.DropTable(
                name: "SignatureReferences");

            migrationBuilder.DropTable(
                name: "StaticKeys");

            migrationBuilder.DropTable(
                name: "StaticSignatures");

            migrationBuilder.DropTable(
                name: "TargetPids");

            migrationBuilder.DropTable(
                name: "TargetUrls");

            migrationBuilder.DropTable(
                name: "TCDomains");

            migrationBuilder.DropTable(
                name: "TCEmails");

            migrationBuilder.DropTable(
                name: "TCHashes");

            migrationBuilder.DropTable(
                name: "TCIps");

            migrationBuilder.DropTable(
                name: "TCReferences");

            migrationBuilder.DropTable(
                name: "TCResolutions");

            migrationBuilder.DropTable(
                name: "TCScans");

            migrationBuilder.DropTable(
                name: "TCSubdomanins");

            migrationBuilder.DropTable(
                name: "VirusTotalComments");

            migrationBuilder.DropTable(
                name: "VirusTotalScans");

            migrationBuilder.DropTable(
                name: "YaraDroppeds");

            migrationBuilder.DropTable(
                name: "PeExports");

            migrationBuilder.DropTable(
                name: "PeImports");

            migrationBuilder.DropTable(
                name: "MarkCalls");

            migrationBuilder.DropTable(
                name: "CuckooBehaviors");

            migrationBuilder.DropTable(
                name: "CuckooTargets");

            migrationBuilder.DropTable(
                name: "ThreatCrowdInfo");

            migrationBuilder.DropTable(
                name: "VirusTotalInfo");

            migrationBuilder.DropTable(
                name: "CuckooDroppeds");

            migrationBuilder.DropTable(
                name: "CuckooStatics");

            migrationBuilder.DropTable(
                name: "Marks");

            migrationBuilder.DropTable(
                name: "CuckooInfos");

            migrationBuilder.DropTable(
                name: "CuckooSignatures");

            migrationBuilder.DropTable(
                name: "Malwares");
        }
    }
}
