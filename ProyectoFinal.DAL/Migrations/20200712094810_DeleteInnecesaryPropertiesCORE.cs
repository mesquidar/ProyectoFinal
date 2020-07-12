using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ProyectoFinal.DAL.Migrations
{
    public partial class DeleteInnecesaryPropertiesCORE : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MarkArguments");

            migrationBuilder.DropTable(
                name: "MarkSections");

            migrationBuilder.DropTable(
                name: "VirusTotalComments");

            migrationBuilder.DropTable(
                name: "MarkCalls");

            migrationBuilder.DropColumn(
                name: "Markcount",
                table: "CuckooSignatures");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Markcount",
                table: "CuckooSignatures",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "MarkCalls",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Api = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Mark_Id = table.Column<int>(type: "int", nullable: false),
                    Status = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkCalls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkCalls_Marks_Mark_Id",
                        column: x => x.Mark_Id,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MarkSections",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Entropy = table.Column<long>(type: "bigint", nullable: false),
                    Mark_Id = table.Column<int>(type: "int", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SizeOfData = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VirtualAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    VirtualSize = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkSections", x => x.id);
                    table.ForeignKey(
                        name: "FK_MarkSections_Marks_Mark_Id",
                        column: x => x.Mark_Id,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalComments",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Comment = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Date = table.Column<DateTime>(type: "datetime2", nullable: false),
                    VirusTotalId = table.Column<int>(type: "int", nullable: true),
                    VirusTotal_Id = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalComments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalComments_VirusTotalInfos_VirusTotalId",
                        column: x => x.VirusTotalId,
                        principalTable: "VirusTotalInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "MarkArguments",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Access = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    AllocationType = table.Column<long>(type: "bigint", nullable: true),
                    BaseAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    BaseHandle = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    FreeBytes = table.Column<long>(type: "bigint", nullable: true),
                    KeyHandle = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Length = table.Column<long>(type: "bigint", nullable: true),
                    MarkCall_Id = table.Column<int>(type: "int", nullable: false),
                    Options = table.Column<long>(type: "bigint", nullable: true),
                    ProcessHandle = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ProcessIdentifier = table.Column<int>(type: "int", nullable: true),
                    Protection = table.Column<int>(type: "int", nullable: true),
                    RegionSize = table.Column<long>(type: "bigint", nullable: true),
                    Regkey = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RegkeyR = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RootPath = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TotalNumberOfBytes = table.Column<double>(type: "float", nullable: true),
                    TotalNumberOfFreeBytes = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkArguments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkArguments_MarkCalls_MarkCall_Id",
                        column: x => x.MarkCall_Id,
                        principalTable: "MarkCalls",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MarkArguments_MarkCall_Id",
                table: "MarkArguments",
                column: "MarkCall_Id");

            migrationBuilder.CreateIndex(
                name: "IX_MarkCalls_Mark_Id",
                table: "MarkCalls",
                column: "Mark_Id");

            migrationBuilder.CreateIndex(
                name: "IX_MarkSections_Mark_Id",
                table: "MarkSections",
                column: "Mark_Id");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalComments_VirusTotalId",
                table: "VirusTotalComments",
                column: "VirusTotalId");
        }
    }
}
