import { BlockType } from '../enums/block-type.enum';

export interface IBlock {
  id: string;
  type: BlockType;
  content: string;
  order: number;
  subsection: ISubsection;
  createdAt?: Date;
  updatedAt?: Date;
  deletedAt?: Date | null;
}

export interface ISubsection {
  id: string;
  title: string;
  order: number;
  section: ISection;
  blocks: IBlock[];
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export interface ISection {
  id: string;
  title: string;
  order: number;
  manual: IManual;
  subsections: ISubsection[];
  createdAt?: Date;
  updatedAt?: Date;
  deletedAt?: Date | null;
}

export interface IManual {
  id: string;
  title: string;
  sections: ISection[];
  createdAt?: Date;
  updatedAt?: Date;
  deletedAt?: Date | null;
}
