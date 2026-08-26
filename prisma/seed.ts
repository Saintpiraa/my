import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../src/generated/prisma/client";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL is not defined in your .env file");
}

const adapter = new PrismaPg({
  connectionString,
});

const prisma = new PrismaClient({
  adapter,
});

const porkCuts = [
  {
    name: "Pork Belly",
    slug: "pork-belly",
    category: "RICH • TENDER • FLAVOURFUL",
    description:
      "Pork belly comes from the underside of the animal and is known for its generous fat content and rich flavour.",
    image: "/belly-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: true,
  },
  {
    name: "Pork Ribs",
    slug: "pork-ribs",
    category: "JUICY • MEATY • GRILL-READY",
    description:
      "Pork ribs contain meat attached to the rib bones and are especially popular for grilling, roasting and barbecue-style cooking.",
    image: "/ribs-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: true,
  },
  {
    name: "Pork Loin",
    slug: "pork-loin",
    category: "LEAN • TENDER • VERSATILE",
    description:
      "The loin runs along the back of the pig and produces several popular cuts, including chops and roasts.",
    image: "/loin-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: true,
  },
  {
    name: "Pork Shoulder",
    slug: "pork-shoulder",
    category: "JUICY • MARBLED • SLOW-COOKED",
    description:
      "The shoulder contains more fat and connective tissue than leaner areas, making it particularly suitable for slow cooking.",
    image: "/shoulder-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: false,
  },
  {
    name: "Pork Leg",
    slug: "pork-leg",
    category: "LEAN • MEATY • ROAST-READY",
    description:
      "The pork leg comes from the rear of the animal and provides substantial, lean meat suitable for several preparations.",
    image: "/leg-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: false,
  },
  {
    name: "Pork Chops",
    slug: "pork-chops",
    category: "TENDER • QUICK • CLASSIC",
    description:
      "Pork chops can be cut from different sections of the loin, giving them different textures and fat levels.",
    image: "/chops-1.jpg",
    pricePerKg: 600,
    costPerKg: 0,
    availableKg: 0,
    isActive: true,
    isFeatured: false,
  },
];

async function main() {
  console.log("🌱 Seeding Taviv database...");

  for (const porkCut of porkCuts) {
    const result = await prisma.porkCut.upsert({
      where: {
        slug: porkCut.slug,
      },
      update: {
        name: porkCut.name,
        category: porkCut.category,
        description: porkCut.description,
        image: porkCut.image,
        pricePerKg: porkCut.pricePerKg,
        isActive: porkCut.isActive,
        isFeatured: porkCut.isFeatured,
      },
      create: porkCut,
    });

    console.log(`✓ ${result.name}`);
  }

  console.log("✅ Taviv pork cuts seeded successfully.");
}

main()
  .catch((error) => {
    console.error("❌ Seed failed:");
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
  